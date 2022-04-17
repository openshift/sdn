package openshift_sdn_node

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/cobra"
	"k8s.io/klog/v2"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	utilwait "k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/record"
	kubeproxyconfig "k8s.io/kubernetes/pkg/proxy/apis/config"
	"k8s.io/kubernetes/pkg/util/interrupt"
	"k8s.io/kubernetes/pkg/util/iptables"
	kexec "k8s.io/utils/exec"
	"sigs.k8s.io/yaml"

	"github.com/openshift/library-go/pkg/serviceability"
	sdnnode "github.com/openshift/sdn/pkg/network/node"
	sdnproxy "github.com/openshift/sdn/pkg/network/proxy"
	"github.com/openshift/sdn/pkg/version"
)

// openShiftSDN stores the variables needed to initialize the real networking
// processess from the command line.
type openShiftSDN struct {
	nodeName     string
	nodeIP       string
	platformType string

	proxyConfigFilePath string
	proxyConfig         *kubeproxyconfig.KubeProxyConfiguration

	mtuOverrideFilePath string
	overrideMTU         uint32
	routableMTU         uint32

	informers   *sdnInformers
	osdnNode    *sdnnode.OsdnNode
	sdnRecorder record.EventRecorder
	osdnProxy   *sdnproxy.OsdnProxy

	ipt iptables.Interface
}

var networkLong = `
Start OpenShift SDN node components. This includes the service proxy.
`

func NewOpenShiftSDNCommand(basename string, errout io.Writer) *cobra.Command {
	sdn := &openShiftSDN{}

	cmd := &cobra.Command{
		Use:   basename,
		Short: "Start OpenShiftSDN",
		Long:  networkLong,
		Run: func(c *cobra.Command, _ []string) {
			ch := make(chan struct{})
			interrupt.New(func(s os.Signal) {
				fmt.Fprintf(errout, "interrupt: Signal %s received. Gracefully shutting down ...\n", s.String())
				close(ch)
			}).Run(func() error {
				sdn.run(c, errout, ch)
				return nil
			})
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&sdn.nodeName, "node-name", "", "Kubernetes node name")
	cmd.MarkFlagRequired("node-name")
	flags.StringVar(&sdn.nodeIP, "node-ip", "", "Kubernetes node IP")
	cmd.MarkFlagRequired("node-ip")
	flags.StringVar(&sdn.proxyConfigFilePath, "proxy-config", "", "Location of the kube-proxy configuration file")
	cmd.MarkFlagRequired("proxy-config")
	flags.StringVar(&sdn.platformType, "platform-type", "", "The cloud provider platform type openshift-sdn is deployed on")
	flags.StringVar(&sdn.mtuOverrideFilePath, "mtu-override", "", "Location of an MTU-override configuration file")

	return cmd
}

// run starts the network process. Does not return.
func (sdn *openShiftSDN) run(c *cobra.Command, errout io.Writer, stopCh chan struct{}) {
	// Parse config file, build config objects
	err := sdn.validateAndParse()
	if err != nil {
		if kerrors.IsInvalid(err) {
			if details := err.(*kerrors.StatusError).ErrStatus.Details; details != nil {
				fmt.Fprintf(errout, "Invalid %s %s\n", details.Kind, details.Name)
				for _, cause := range details.Causes {
					fmt.Fprintf(errout, "  %s: %s\n", cause.Field, cause.Message)
				}
				os.Exit(255)
			}
		}
		klog.Fatal(err)
	}

	// Set up a watch on our config file; if it changes, we should exit -
	// (we don't have the ability to dynamically reload config changes).
	if err := watchForChanges(sdn.proxyConfigFilePath, stopCh); err != nil {
		klog.Fatalf("unable to setup configuration watch: %v", err)
	}

	// Build underlying network objects
	err = sdn.init()
	if err != nil {
		klog.Fatalf("Failed to initialize sdn: %v", err)
	}

	err = sdn.start(stopCh)
	if err != nil {
		klog.Fatalf("Failed to start sdn: %v", err)
	}

	<-stopCh
	time.Sleep(500 * time.Millisecond) // gracefully shut down
}

// validateAndParse validates the command line options, parses the node
// configuration, and builds the upstream proxy configuration.
func (sdn *openShiftSDN) validateAndParse() error {
	klog.V(2).Infof("Reading proxy configuration from %s", sdn.proxyConfigFilePath)
	var err error
	sdn.proxyConfig, err = readProxyConfig(sdn.proxyConfigFilePath)
	if err != nil {
		return err
	}

	if sdn.mtuOverrideFilePath != "" {
		klog.V(2).Infof("Reading MTU override from %s", sdn.mtuOverrideFilePath)
		sdn.overrideMTU, sdn.routableMTU, err = readMTUOverride(sdn.mtuOverrideFilePath)
		if err != nil {
			return err
		}
	}

	return nil
}

// init builds the underlying structs for the network processes.
func (sdn *openShiftSDN) init() error {
	// Build the informers
	var err error
	err = sdn.buildInformers()
	if err != nil {
		return fmt.Errorf("failed to build informers: %v", err)
	}

	sdn.ipt = iptables.New(kexec.New(), iptables.ProtocolIPv4)

	// Configure SDN
	err = sdn.initSDN()
	if err != nil {
		return fmt.Errorf("failed to initialize SDN: %v", err)
	}

	// Configure the proxy
	err = sdn.initProxy()
	if err != nil {
		return fmt.Errorf("failed to initialize proxy: %v", err)
	}

	return nil
}

// Start starts the network, proxy, and informers, then returns.
func (sdn *openShiftSDN) start(stopCh <-chan struct{}) error {
	klog.Infof("Starting node networking (%s)", version.Get().String())

	serviceability.StartProfiler()
	err := sdn.runSDN()
	if err != nil {
		return err
	}
	proxyInitChan := make(chan bool)
	sdn.runProxy(proxyInitChan)
	sdn.informers.start(stopCh)

	klog.V(2).Infof("openshift-sdn network plugin waiting for proxy startup to complete")
	<-proxyInitChan
	klog.V(2).Infof("openshift-sdn network plugin registering startup")
	if err := sdn.writeConfigFile(); err != nil {
		klog.Fatal(err)
	}
	klog.V(2).Infof("openshift-sdn network plugin ready")

	go sdn.ipt.Monitor(iptables.Chain("OPENSHIFT-SDN-CANARY"),
		[]iptables.Table{iptables.TableMangle, iptables.TableNAT, iptables.TableFilter},
		sdn.reloadIPTables,
		sdn.proxyConfig.IPTables.SyncPeriod.Duration,
		utilwait.NeverStop)

	return nil
}

// reloadIPTables reloads node and proxy iptables rules after a flush
func (sdn *openShiftSDN) reloadIPTables() {
	if err := sdn.osdnNode.ReloadIPTables(); err != nil {
		klog.Errorf("Reloading openshift node iptables rules failed: %v", err)
	}
	if sdn.osdnProxy != nil {
		if err := sdn.osdnProxy.ReloadIPTables(); err != nil {
			klog.Errorf("Reloading openshift proxy iptables rules failed: %v", err)
		}
	}
}

// watchForChanges closes stopCh if the configuration file changed.
func watchForChanges(configPath string, stopCh chan struct{}) error {
	configPath, err := filepath.Abs(configPath)
	if err != nil {
		return err
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}

	// Watch all symlinks for changes
	p := configPath
	maxdepth := 100
	for depth := 0; depth < maxdepth; depth++ {
		if err := watcher.Add(p); err != nil {
			return err
		}
		klog.V(2).Infof("Watching config file %s for changes", p)

		stat, err := os.Lstat(p)
		if err != nil {
			return err
		}

		// configmaps are usually symlinks
		if stat.Mode()&os.ModeSymlink > 0 {
			p, err = filepath.EvalSymlinks(p)
			if err != nil {
				return err
			}
		} else {
			break
		}
	}

	go func() {
		for {
			select {
			case <-stopCh:
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				klog.V(2).Infof("Configuration file %s changed, exiting...", event.Name)
				close(stopCh)
				return
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				klog.V(4).Infof("fsnotify error %v", err)
			}
		}
	}()
	return nil
}

// readMTUOverride reads the --mtu-override file, if any
func readMTUOverride(file string) (uint32, uint32, error) {
	bytes, err := os.ReadFile(file)
	if err != nil {
		return 0, 0, err
	}

	conf := struct {
		OverlayMTU  uint32 `json:"mtu"`
		RoutableMTU uint32 `json:"routable-mtu"`
	}{}
	err = yaml.Unmarshal(bytes, &conf)
	if err != nil {
		return 0, 0, err
	}

	return conf.OverlayMTU, conf.RoutableMTU, err
}
