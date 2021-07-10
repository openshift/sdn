package ovs

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"time"

	metrics "github.com/openshift/sdn/pkg/network/node/metrics"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	utilwait "k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"
	"k8s.io/utils/exec"
)

// Interface represents an interface to OVS
type Interface interface {
	// AddBridge creates the bridge associated with the interface, optionally setting
	// properties on it (as with "ovs-vsctl set Bridge ..."). If the bridge already
	// exists, this will NOT result in error since it sets --may-exist internally.
	AddBridge(properties ...string) error

	// DeleteBridge deletes the bridge associated with the interface. This always
	// calls del-br by passing the --if-exists flag so the resulting call
	// will not error out if the bridge doesn't exist
	DeleteBridge() error

	// AddPort adds an interface to the bridge, requesting the indicated port
	// number, and optionally setting properties on it (as with "ovs-vsctl set
	// Interface ..."). Returns the allocated port number (or an error).
	AddPort(port string, ofportRequest int, properties ...string) (int, error)

	// DeletePort removes an interface from the bridge. (It is not an
	// error if the interface is not currently a bridge port.)
	DeletePort(port string) error

	// DumpGroup dumps the groups table for the bridge and returns it as an array of stings
	// Currently DumpGroups is only used in testing
	DumpGroups() ([]string, error)

	// GetOFPort returns the OpenFlow port number of a given network interface
	// attached to a bridge.
	GetOFPort(port string) (int, error)

	// SetFrags sets the fragmented-packet-handling mode (as with
	// "ovs-ofctl set-frags")
	SetFrags(mode string) error

	// Create creates a record in the OVS database, as with "ovs-vsctl create" and
	// returns the UUID of the newly-created item.
	// NOTE: This only works for QoS; for all other tables the created object will
	// immediately be garbage-collected; we'd need an API that calls "create" and "set"
	// in the same "ovs-vsctl" call.
	Create(table string, values ...string) (string, error)

	// Destroy deletes the indicated record in the OVS database. It is not an error if
	// the record does not exist
	Destroy(table, record string) error

	// Get gets the indicated value from the OVS database. For multi-valued or
	// map-valued columns, the data is returned in the same format as "ovs-vsctl get".
	Get(table, record, column string) (string, error)

	// Set sets one or more columns on a record in the OVS database, as with
	// "ovs-vsctl set"
	Set(table, record string, values ...string) error

	// Clear unsets the indicated columns in the OVS database. It is not an error if
	// the value is already unset
	Clear(table, record string, columns ...string) error

	// Find finds records in the OVS database that match the given condition.
	// It returns the value of the given columns of matching records.
	Find(table string, column []string, condition string) ([]map[string]string, error)

	// FindOne is like Find but returns only a single column
	FindOne(table, column, condition string) ([]string, error)

	// DumpFlows dumps the flow table for the bridge and returns it as an array of
	// strings, one per flow. If flow is not "" then it describes the flows to dump.
	DumpFlows(flow string, args ...interface{}) ([]string, error)

	// NewTransaction begins a new OVS transaction.
	NewTransaction() Transaction

	// UpdateOVSMetrics runs a Dumpflows transaction and sets the gauge with the existing amount of flows
	UpdateOVSMetrics()
}

// Transaction manages a single set of OVS flow modifications
type Transaction interface {
	// AddFlow prepares adding a flow to the bridge.
	// Given flow is cached but not executed at this time.
	// The arguments are passed to fmt.Sprintf().
	AddFlow(flow string, args ...interface{})

	// DeleteFlows prepares deleting all matching flows from the bridge.
	// Given flow is cached but not executed at this time.
	// The arguments are passed to fmt.Sprintf().
	DeleteFlows(flow string, args ...interface{})

	AddGroup(groupID uint32, groupType string, buckets []string)
	DeleteGroup(groupID uint32)

	// Commit executes all cached flows as a single atomic transaction and
	// returns any error that occurred during the transaction.
	Commit() error
}

const (
	OVS_OFCTL = "ovs-ofctl"
	OVS_VSCTL = "ovs-vsctl"
)

var ovsBackoff utilwait.Backoff = utilwait.Backoff{
	Duration: 10 * time.Millisecond,
	Factor:   1.25,
	Steps:    4,
}

// ovsExec implements ovs.Interface via calls to ovs-ofctl and ovs-vsctl
type ovsExec struct {
	execer exec.Interface
	bridge string
}

// New returns a new ovs.Interface
func New(execer exec.Interface, bridge string) (Interface, error) {
	if _, err := execer.LookPath(OVS_OFCTL); err != nil {
		return nil, fmt.Errorf("OVS is not installed")
	}
	if _, err := execer.LookPath(OVS_VSCTL); err != nil {
		return nil, fmt.Errorf("OVS is not installed")
	}

	return &ovsExec{execer: execer, bridge: bridge}, nil
}

func (ovsif *ovsExec) execWithStdin(cmd string, stdinArgs []string, args ...string) (string, error) {
	logLevel := klog.Level(4)
	switch cmd {
	case OVS_OFCTL:
		if args[0] == "dump-flows" {
			logLevel = klog.Level(5)
		}
		args = append([]string{"-O", "OpenFlow13"}, args...)
	case OVS_VSCTL:
		args = append([]string{"--timeout=30"}, args...)
	}

	kcmd := ovsif.execer.Command(cmd, args...)
	if stdinArgs != nil {
		stdinString := strings.Join(stdinArgs, "\n")
		stdin := bytes.NewBufferString(stdinString)
		kcmd.SetStdin(stdin)

		klog.V(logLevel).Infof("Executing: %s %s <<\n%s", cmd, strings.Join(args, " "), stdinString)
	} else {
		klog.V(logLevel).Infof("Executing: %s %s", cmd, strings.Join(args, " "))
	}

	output, err := kcmd.CombinedOutput()
	if err != nil {
		klog.Errorf("Error executing cmd: %s with args: %v, output: \n%s", cmd, args, string(output))
		return "", err
	}

	outStr := string(output)
	if outStr != "" {
		// If output is a single line, strip the trailing newline
		nl := strings.Index(outStr, "\n")
		if nl == len(outStr)-1 {
			outStr = outStr[:nl]
		}
	}
	return outStr, nil
}

func (ovsif *ovsExec) exec(cmd string, args ...string) (string, error) {
	var output string
	var err error
	return output, utilwait.ExponentialBackoff(ovsBackoff, func() (bool, error) {
		output, err = ovsif.execWithStdin(cmd, nil, args...)
		if err == nil {
			metrics.OVSOperationsResult.WithLabelValues(metrics.OVSOperationSuccess).Inc()
			return true, nil
		}
		metrics.OVSOperationsResult.WithLabelValues(metrics.OVSOperationFailure).Inc()
		return false, nil
	})
}

func validateColumns(columns ...string) error {
	for _, col := range columns {
		end := strings.IndexAny(col, ":=")
		if end != -1 {
			col = col[:end]
		}
		if strings.Contains(col, "-") {
			return fmt.Errorf("bad ovsdb column name %q: should be %q", col, strings.Replace(col, "-", "_", -1))
		}
	}
	return nil
}

func (ovsif *ovsExec) AddBridge(properties ...string) error {
	args := []string{"--may-exist", "add-br", ovsif.bridge}
	if len(properties) > 0 {
		if err := validateColumns(properties...); err != nil {
			return err
		}
		args = append(args, "--", "set", "Bridge", ovsif.bridge)
		args = append(args, properties...)
	}
	_, err := ovsif.exec(OVS_VSCTL, args...)
	return err
}

func (ovsif *ovsExec) DeleteBridge() error {
	args := []string{"--if-exists", "del-br", ovsif.bridge}
	_, err := ovsif.exec(OVS_VSCTL, args...)
	return err
}

func (ovsif *ovsExec) GetOFPort(port string) (int, error) {
	ofportStr, err := ovsif.exec(OVS_VSCTL, "get", "Interface", port, "ofport")
	if err != nil {
		return -1, fmt.Errorf("failed to get OVS port for %s: %v", port, err)
	}
	ofport, err := strconv.Atoi(ofportStr)
	if err != nil {
		return -1, fmt.Errorf("could not parse allocated ofport %q: %v", ofportStr, err)
	}
	if ofport == -1 {
		errStr, err := ovsif.exec(OVS_VSCTL, "get", "Interface", port, "error")
		if err != nil || errStr == "" {
			errStr = "unknown error"
		}
		return -1, fmt.Errorf("error on port %s: %s", port, errStr)
	}
	return ofport, nil
}

func (ovsif *ovsExec) AddPort(port string, ofportRequest int, properties ...string) (int, error) {
	args := []string{"--may-exist", "add-port", ovsif.bridge, port}
	if ofportRequest > 0 || len(properties) > 0 {
		args = append(args, "--", "set", "Interface", port)
		if ofportRequest > 0 {
			args = append(args, fmt.Sprintf("ofport_request=%d", ofportRequest))
		}
		if len(properties) > 0 {
			if err := validateColumns(properties...); err != nil {
				return -1, err
			}
			args = append(args, properties...)
		}
	}
	_, err := ovsif.exec(OVS_VSCTL, args...)
	if err != nil {
		return -1, err
	}
	ofport, err := ovsif.GetOFPort(port)
	if err != nil {
		return -1, err
	}
	if ofportRequest > 0 && ofportRequest != ofport {
		return -1, fmt.Errorf("allocated ofport (%d) did not match request (%d)", ofport, ofportRequest)
	}
	return ofport, nil
}

func (ovsif *ovsExec) DeletePort(port string) error {
	_, err := ovsif.exec(OVS_VSCTL, "--if-exists", "del-port", ovsif.bridge, port)
	return err
}

// Currently DumpGroups is only used for testing
func (ovsif *ovsExec) DumpGroups() ([]string, error) {
	//stub
	return nil, fmt.Errorf("Dump Groups is not implemented")

}

func (ovsif *ovsExec) SetFrags(mode string) error {
	_, err := ovsif.exec(OVS_OFCTL, "set-frags", ovsif.bridge, mode)
	return err
}

func (ovsif *ovsExec) Create(table string, values ...string) (string, error) {
	if err := validateColumns(values...); err != nil {
		return "", err
	}
	args := append([]string{"create", table}, values...)
	return ovsif.exec(OVS_VSCTL, args...)
}

func (ovsif *ovsExec) Destroy(table, record string) error {
	_, err := ovsif.exec(OVS_VSCTL, "--if-exists", "destroy", table, record)
	return err
}

func (ovsif *ovsExec) Get(table, record, column string) (string, error) {
	if err := validateColumns(column); err != nil {
		return "", err
	}
	return ovsif.exec(OVS_VSCTL, "get", table, record, column)
}

func (ovsif *ovsExec) Set(table, record string, values ...string) error {
	if err := validateColumns(values...); err != nil {
		return err
	}
	args := append([]string{"set", table, record}, values...)
	_, err := ovsif.exec(OVS_VSCTL, args...)
	return err
}

func (ovsif *ovsExec) Find(table string, columns []string, condition string) ([]map[string]string, error) {
	if err := validateColumns(columns...); err != nil {
		return nil, err
	}
	if err := validateColumns(condition); err != nil {
		return nil, err
	}
	output, err := ovsif.exec(OVS_VSCTL, "--columns="+strings.Join(columns, ","), "find", table, condition)
	if err != nil {
		return nil, err
	}
	output = strings.TrimSuffix(output, "\n")
	if output == "" {
		return nil, err
	}

	rows := strings.Split(output, "\n\n")
	result := make([]map[string]string, len(rows))
	for i, row := range rows {
		cols := make(map[string]string)
		for _, col := range strings.Split(row, "\n") {
			data := strings.SplitN(col, ":", 2)
			if len(data) != 2 {
				return nil, fmt.Errorf("bad 'ovs-vsctl find' line %q", col)
			}
			name := strings.TrimSpace(data[0])
			val := strings.TrimSpace(data[1])
			// We want "bare" values for strings, but we can't pass --bare to
			// ovs-vsctl because it breaks more complicated types. So try
			// passing each value through Unquote(); if it fails, that means
			// the value wasn't a quoted string, so use it as-is.
			if unquoted, err := strconv.Unquote(val); err == nil {
				val = unquoted
			}
			cols[name] = val
		}
		result[i] = cols
	}

	return result, nil
}

func (ovsif *ovsExec) FindOne(table, column, condition string) ([]string, error) {
	fullResult, err := ovsif.Find(table, []string{column}, condition)
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(fullResult))
	for _, row := range fullResult {
		result = append(result, row[column])
	}
	return result, nil
}

func (ovsif *ovsExec) Clear(table, record string, columns ...string) error {
	if err := validateColumns(columns...); err != nil {
		return err
	}
	args := append([]string{"--if-exists", "clear", table, record}, columns...)
	_, err := ovsif.exec(OVS_VSCTL, args...)
	return err
}

func (ovsif *ovsExec) DumpFlows(flow string, args ...interface{}) ([]string, error) {
	if len(args) > 0 {
		flow = fmt.Sprintf(flow, args...)
	}
	out, err := ovsif.exec(OVS_OFCTL, "dump-flows", ovsif.bridge, flow)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(out, "\n")
	flows := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.Contains(line, "cookie=") {
			flows = append(flows, line)
		}
	}
	return flows, nil
}

func (ovsif *ovsExec) NewTransaction() Transaction {
	return &ovsExecTx{ovsif: ovsif, mods: []string{}}
}

// bundle executes all given flows as a single atomic transaction
func (ovsif *ovsExec) bundle(flows []string) error {
	if len(flows) == 0 {
		return nil
	}

	_, err := ovsif.execWithStdin(OVS_OFCTL, flows, "bundle", ovsif.bridge, "-")
	return err
}

func (ovsif *ovsExec) UpdateOVSMetrics() {
	flows, err := ovsif.DumpFlows("")
	if err == nil {
		metrics.OVSFlows.Set(float64(len(flows)))
	} else {
		utilruntime.HandleError(fmt.Errorf("failed to dump OVS flows for metrics: %v", err))
	}
}

// ovsExecTx implements ovs.Transaction and maintains current flow context
type ovsExecTx struct {
	ovsif *ovsExec
	mods  []string
}

func (tx *ovsExecTx) AddFlow(flow string, args ...interface{}) {
	if len(args) > 0 {
		flow = fmt.Sprintf(flow, args...)
	}
	tx.mods = append(tx.mods, fmt.Sprintf("flow add %s", flow))
}

func (tx *ovsExecTx) DeleteFlows(flow string, args ...interface{}) {
	if len(args) > 0 {
		flow = fmt.Sprintf(flow, args...)
	}
	tx.mods = append(tx.mods, fmt.Sprintf("flow delete %s", flow))
}

func (tx *ovsExecTx) AddGroup(groupID uint32, groupType string, buckets []string) {
	tx.mods = append(tx.mods, fmt.Sprintf("group add group_id=%d,type=%s,bucket=%s", groupID, groupType, strings.Join(buckets, "bucket=")))
}

func (tx *ovsExecTx) DeleteGroup(groupID uint32) {
	tx.mods = append(tx.mods, fmt.Sprintf("group delete group_id=%d", groupID))
}

func (tx *ovsExecTx) Commit() error {
	defer func() {
		tx.mods = []string{}
	}()
	return utilwait.ExponentialBackoff(ovsBackoff, func() (bool, error) {
		err := tx.ovsif.bundle(tx.mods)
		if err == nil {
			metrics.OVSOperationsResult.WithLabelValues(metrics.OVSOperationSuccess).Inc()
			return true, nil
		}
		metrics.OVSOperationsResult.WithLabelValues(metrics.OVSOperationFailure).Inc()
		return false, nil
	})
}
