package openshift_sdn

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
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	utilwait "k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/record"
	kubeproxyconfig "k8s.io/kubernetes/pkg/proxy/apis/config"
	"k8s.io/kubernetes/pkg/util/interrupt"
	"k8s.io/kubernetes/pkg/util/iptables"
	kexec "k8s.io/utils/exec"

	"github.com/openshift/library-go/pkg/serviceability"
	sdnnode "github.com/openshift/sdn/pkg/network/node"
	sdnproxy "github.com/openshift/sdn/pkg/network/proxy"
	"github.com/openshift/sdn/pkg/version"
)

// OpenShiftSDN stores the variables needed to initialize the real networking
// processess from the command line.
type OpenShiftSDN struct {
	nodeName string
	nodeIP   string

	ProxyConfigFilePath string
	ProxyConfig         *kubeproxyconfig.KubeProxyConfiguration

	informers   *informers
	OsdnNode    *sdnnode.OsdnNode
	sdnRecorder record.EventRecorder
	OsdnProxy   *sdnproxy.OsdnProxy

	ipt iptables.Interface
}

var networkLong = `
Start OpenShift SDN node components. This includes the service proxy.
`

func NewOpenShiftSDNCommand(basename string, errout io.Writer) *cobra.Command {
	sdn := &OpenShiftSDN{}

	cmd := &cobra.Command{
		Use:   basename,
		Short: "Start OpenShiftSDN",
		Long:  networkLong,
		Run: func(c *cobra.Command, _ []string) {
			ch := make(chan struct{})
			interrupt.New(func(s os.Signal) {
				fmt.Fprintf(errout, "interrupt: Gracefully shutting down ...\n")
				close(ch)
			}).Run(func() error {
				sdn.Run(c, errout, ch)
				return nil
			})
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&sdn.nodeName, "node-name", "", "Kubernetes node name")
	cmd.MarkFlagRequired("node-name")
	flags.StringVar(&sdn.nodeIP, "node-ip", "", "Kubernetes node IP")
	cmd.MarkFlagRequired("node-ip")
	flags.StringVar(&sdn.ProxyConfigFilePath, "proxy-config", "", "Location of the kube-proxy configuration file")
	cmd.MarkFlagRequired("proxy-config")

	return cmd
}

// Run starts the network process. Does not return.
func (sdn *OpenShiftSDN) Run(c *cobra.Command, errout io.Writer, stopCh chan struct{}) {
	// Parse config file, build config objects
	err := sdn.ValidateAndParse()
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
	if err := watchForChanges(sdn.ProxyConfigFilePath, stopCh); err != nil {
		klog.Fatalf("unable to setup configuration watch: %v", err)
	}

	// Build underlying network objects
	err = sdn.Init()
	if err != nil {
		klog.Fatalf("Failed to initialize sdn: %v", err)
	}

	err = sdn.Start(stopCh)
	if err != nil {
		klog.Fatalf("Failed to start sdn: %v", err)
	}

	<-stopCh
	time.Sleep(500 * time.Millisecond) // gracefully shut down
}

// ValidateAndParse validates the command line options, parses the node
// configuration, and builds the upstream proxy configuration.
func (sdn *OpenShiftSDN) ValidateAndParse() error {
	klog.V(2).Infof("Reading proxy configuration from %s", sdn.ProxyConfigFilePath)
	var err error
	sdn.ProxyConfig, err = readProxyConfig(sdn.ProxyConfigFilePath)
	if err != nil {
		return err
	}

	return nil
}

// Init builds the underlying structs for the network processes.
func (sdn *OpenShiftSDN) Init() error {
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
func (sdn *OpenShiftSDN) Start(stopCh <-chan struct{}) error {
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
		sdn.ProxyConfig.IPTables.SyncPeriod.Duration,
		utilwait.NeverStop)

	return nil
}

// reloadIPTables reloads node and proxy iptables rules after a flush
func (sdn *OpenShiftSDN) reloadIPTables() {
	if err := sdn.OsdnNode.ReloadIPTables(); err != nil {
		utilruntime.HandleError(fmt.Errorf("Reloading openshift node iptables rules failed: %v", err))
	}
	if sdn.OsdnProxy != nil {
		if err := sdn.OsdnProxy.ReloadIPTables(); err != nil {
			utilruntime.HandleError(fmt.Errorf("Reloading openshift proxy iptables rules failed: %v", err))
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
