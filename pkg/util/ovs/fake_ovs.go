package ovs

import (
	"fmt"
	"sort"
	"strings"
)

// ovsFake implements a fake ovs.Interface for testing purposes
//
// Note that the code here is *not* expected to be 100% equivalent to ovsExec, as
// that would require porting over huge amounts of ovs-ofctl source code. It needs
// to support enough features to make the SDN unit tests pass, and should do enough
// error checking to catch bugs that have tripped us up in the past (eg,
// specifying "nw_dst" without "ip").

type ovsPortInfo struct {
	ofport      int
	externalIDs map[string]string
	dst_port    string
}

type ovsFake struct {
	bridge string

	ports map[string]ovsPortInfo
	// map of groupID to OVS group, makes it easier to add and delete groups
	groups map[string]OVSGroup
	flows  ovsFlows
}

// NewFake returns a new ovs.Interface
func NewFake(bridge string) Interface {
	return &ovsFake{bridge: bridge, groups: make(map[string]OVSGroup)}
}

func (fake *ovsFake) AddBridge(properties ...string) error {
	if err := validateColumns(properties...); err != nil {
		return err
	}
	fake.ports = make(map[string]ovsPortInfo)
	fake.flows = make([]OvsFlow, 0)
	return nil
}

func (fake *ovsFake) DeleteBridge() error {
	fake.ports = nil
	fake.flows = nil
	return nil
}

func (fake *ovsFake) ensureExists() error {
	if fake.ports == nil {
		return fmt.Errorf("no bridge named %s", fake.bridge)
	}
	return nil
}

func (fake *ovsFake) GetOFPort(port string) (int, error) {
	if err := fake.ensureExists(); err != nil {
		return -1, err
	}

	if portInfo, exists := fake.ports[port]; exists {
		return portInfo.ofport, nil
	} else {
		return -1, fmt.Errorf("no row %q in table Interface", port)
	}
}

func (fake *ovsFake) AddPort(port string, ofportRequest int, properties ...string) (int, error) {
	if err := fake.ensureExists(); err != nil {
		return -1, err
	}
	if err := validateColumns(properties...); err != nil {
		return -1, err
	}

	var externalIDs map[string]string
	var dst_port string
	for _, property := range properties {
		if strings.HasPrefix(property, "external_ids=") {
			var err error
			externalIDs, err = ParseExternalIDs(property[13:])
			if err != nil {
				return -1, err
			}
		}
		if strings.HasPrefix(property, "options:dst_port=") {
			dst_port = property[17:]
		}
	}

	portInfo, exists := fake.ports[port]
	if exists {
		if portInfo.ofport != ofportRequest && ofportRequest != -1 {
			return -1, fmt.Errorf("allocated ofport (%d) did not match request (%d)", portInfo.ofport, ofportRequest)
		}
	} else {
		if ofportRequest == -1 {
			portInfo.ofport = 1
			for _, existingPortInfo := range fake.ports {
				if existingPortInfo.ofport >= portInfo.ofport {
					portInfo.ofport = existingPortInfo.ofport + 1
				}
			}
		} else {
			if ofportRequest < 1 || ofportRequest > 65535 {
				return -1, fmt.Errorf("requested ofport (%d) out of range", ofportRequest)
			}
			portInfo.ofport = ofportRequest
		}
		portInfo.externalIDs = externalIDs
		portInfo.dst_port = dst_port
		fake.ports[port] = portInfo
	}
	return portInfo.ofport, nil
}

func (fake *ovsFake) DeletePort(port string) error {
	if err := fake.ensureExists(); err != nil {
		return err
	}

	delete(fake.ports, port)
	return nil
}

func (fake *ovsFake) DumpGroups() ([]string, error) {
	if err := fake.ensureExists(); err != nil {
		return nil, err
	}

	var groups []string
	//since fake.groups is a map the results are in a random order might cause issues with unit tests in the future
	for _, group := range fake.groups {
		bucketString := "bucket="
		for _, bucket := range group.Buckets {
			actionString := "actions="
			for _, action := range bucket.Actions {
				if action.Name == "ct" {
					actionString = fmt.Sprintf("%s%s%s", actionString, action.Name, action.Value)
				} else {
					actionString = fmt.Sprintf("%s%s:%s", actionString, action.Name, action.Value)
				}
				actionString = fmt.Sprintf("%s,", actionString)
			}
			bucketString = fmt.Sprintf("%s%s,", bucketString, actionString[:len(actionString)-1])

		}
		groups = append(groups, fmt.Sprintf("group_id=%d,type=%s,%s", group.GroupID, group.Type, bucketString[:len(bucketString)-1]))

	}
	return groups, nil

}

func (fake *ovsFake) SetFrags(mode string) error {
	return nil
}

func (ovsif *ovsFake) Create(table string, values ...string) (string, error) {
	if err := validateColumns(values...); err != nil {
		return "", err
	}
	return "fake-UUID", nil
}

func (fake *ovsFake) Destroy(table, record string) error {
	return nil
}

func (fake *ovsFake) Get(table, record, column string) (string, error) {
	if err := validateColumns(column); err != nil {
		return "", err
	}
	if column == "options:dst_port" {
		return fmt.Sprintf("\"%s\"", fake.ports[record].dst_port), nil
	}
	return "", nil
}

func (fake *ovsFake) Set(table, record string, values ...string) error {
	if err := validateColumns(values...); err != nil {
		return err
	}
	return nil
}

func (fake *ovsFake) Find(table string, columns []string, condition string) ([]map[string]string, error) {
	if err := validateColumns(columns...); err != nil {
		return nil, err
	}
	if err := validateColumns(condition); err != nil {
		return nil, err
	}
	results := make([]map[string]string, 0)
	if (table == "Interface" || table == "interface") && strings.HasPrefix(condition, "external_ids:") {
		parsed := strings.Split(condition[13:], "=")
		if len(parsed) != 2 {
			return nil, fmt.Errorf("could not parse condition %q", condition)
		}
		for portName, portInfo := range fake.ports {
			if portInfo.externalIDs[parsed[0]] == parsed[1] {
				result := make(map[string]string)
				for _, column := range columns {
					if column == "name" {
						result[column] = portName
					} else if column == "ofport" {
						result[column] = fmt.Sprintf("%d", portInfo.ofport)
					} else if column == "external_ids" {
						result[column] = UnparseExternalIDs(portInfo.externalIDs)
					}
				}
				results = append(results, result)
			}
		}
	}
	return results, nil
}

func (fake *ovsFake) FindOne(table, column, condition string) ([]string, error) {
	fullResult, err := fake.Find(table, []string{column}, condition)
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(fullResult))
	for _, row := range fullResult {
		result = append(result, row[column])
	}
	return result, nil
}

func (fake *ovsFake) Clear(table, record string, columns ...string) error {
	return nil
}

type ovsFakeTx struct {
	fake   *ovsFake
	flows  []string
	groups []string
}

func (fake *ovsFake) NewTransaction() Transaction {
	return &ovsFakeTx{fake: fake, flows: []string{}, groups: []string{}}
}

func (fake *ovsFake) UpdateOVSMetrics() {
}

// sort.Interface support
type ovsFlows []OvsFlow

func (f ovsFlows) Len() int      { return len(f) }
func (f ovsFlows) Swap(i, j int) { f[i], f[j] = f[j], f[i] }
func (f ovsFlows) Less(i, j int) bool {
	if f[i].Table != f[j].Table {
		return f[i].Table < f[j].Table
	}
	if f[i].Priority != f[j].Priority {
		return f[i].Priority > f[j].Priority
	}
	return f[i].Created.Before(f[j].Created)
}

func fixFlowFields(flow *OvsFlow) {
	// Fix up field names to match what dump-flows prints.  Some fields
	// have aliases or deprecated names that can be used for add/del flows,
	// but dump always reports the canonical name
	if _, isArp := flow.FindField("arp"); isArp {
		for i := range flow.Fields {
			if flow.Fields[i].Name == "nw_src" {
				flow.Fields[i].Name = "arp_spa"
			} else if flow.Fields[i].Name == "nw_dst" {
				flow.Fields[i].Name = "arp_tpa"
			}
		}
	}
}

func (tx *ovsFakeTx) AddFlow(flow string, args ...interface{}) {
	if len(args) > 0 {
		flow = fmt.Sprintf(flow, args...)
	}
	tx.flows = append(tx.flows, fmt.Sprintf("add %s", flow))
}

func (fake *ovsFake) addFlowHelper(flow string) error {
	parsed, err := ParseFlow(ParseForAdd, flow)
	if err != nil {
		return err
	}
	fixFlowFields(parsed)

	// If there is already an exact match for this flow, then the new flow replaces it.
	for i := range fake.flows {
		if FlowMatches(&fake.flows[i], parsed) {
			fake.flows[i] = *parsed
			return nil
		}
	}

	fake.flows = append(fake.flows, *parsed)
	sort.Sort(ovsFlows(fake.flows))
	return nil
}

func (tx *ovsFakeTx) DeleteFlows(flow string, args ...interface{}) {
	if len(args) > 0 {
		flow = fmt.Sprintf(flow, args...)
	}
	tx.flows = append(tx.flows, fmt.Sprintf("delete %s", flow))
}

func (fake *ovsFake) deleteFlowsHelper(flow string) error {
	parsed, err := ParseFlow(ParseForFilter, flow)
	if err != nil {
		return err
	}
	fixFlowFields(parsed)

	newFlows := make([]OvsFlow, 0, len(fake.flows))
	for _, flow := range fake.flows {
		if !FlowMatches(&flow, parsed) {
			newFlows = append(newFlows, flow)
		}
	}
	fake.flows = newFlows
	return nil
}

func (tx *ovsFakeTx) AddGroup(groupID uint32, groupType string, buckets []string) {
	tx.groups = append(tx.groups, fmt.Sprintf("group add group_id=%d,type=%s,bucket=%s", groupID, groupType, strings.Join(buckets, "bucket=")))
}

func (tx *ovsFakeTx) DeleteGroup(groupID uint32) {
	tx.groups = append(tx.groups, fmt.Sprintf("group delete group_id=%d", groupID))
}

func (tx *ovsFakeTx) Commit() error {
	var err error
	if err = tx.fake.ensureExists(); err != nil {
		return err
	}

	for _, group := range tx.groups {
		if strings.HasPrefix(group, "group add") {
			group = strings.TrimPrefix(group, "group add ")
			id := strings.TrimPrefix(strings.Split(group, ",")[0], "group_id=")
			parsed, err := ParseGroup(group)
			if err != nil {
				return fmt.Errorf("cannot parse group %s for group add: %v", group, err)
			}
			tx.fake.groups[id] = *parsed

		}
		if strings.HasPrefix(group, "group delete") {
			group = strings.TrimPrefix(group, "group delete group_id=")
			delete(tx.fake.groups, group)

		}
	}

	oldFlows := make(ovsFlows, len(tx.fake.flows))
	copy(oldFlows, tx.fake.flows)
	for _, flow := range tx.flows {
		if strings.HasPrefix(flow, "add") {
			flow = strings.TrimLeft(flow, "add")
			err = tx.fake.addFlowHelper(flow)
		} else if strings.HasPrefix(flow, "delete") {
			flow = strings.TrimLeft(flow, "delete")
			err = tx.fake.deleteFlowsHelper(flow)
		} else {
			err = fmt.Errorf("invalid flow %q", flow)
		}
		if err != nil {
			// Transaction failed, restore to old state
			tx.fake.flows = oldFlows
			break
		}
	}

	// Reset flows
	tx.flows = []string{}

	return err
}

func (fake *ovsFake) DumpFlows(flow string, args ...interface{}) ([]string, error) {
	if err := fake.ensureExists(); err != nil {
		return nil, err
	}

	// "ParseForFilter", because "ParseForDump" is for the *results* of DumpFlows,
	// not the input
	filter, err := ParseFlow(ParseForFilter, flow, args...)
	if err != nil {
		return nil, err
	}
	fixFlowFields(filter)

	flows := make([]string, 0, len(fake.flows))
	for _, flow := range fake.flows {
		if !FlowMatches(&flow, filter) {
			continue
		}

		str := fmt.Sprintf(" cookie=%s, table=%d", flow.Cookie, flow.Table)
		if flow.Priority != defaultPriority {
			str += fmt.Sprintf(", priority=%d", flow.Priority)
		}
		for _, field := range flow.Fields {
			if field.Value == "" {
				str += fmt.Sprintf(", %s", field.Name)
			} else {
				str += fmt.Sprintf(", %s=%s", field.Name, field.Value)
			}
		}
		actionStr := ""
		for _, action := range flow.Actions {
			if len(actionStr) > 0 {
				actionStr += ","
			}
			actionStr += action.Name
			if action.Value != "" {
				if action.Value[0] != '(' {
					actionStr += ":" + action.Value
				} else {
					actionStr += action.Value
				}
			}
		}
		if len(actionStr) > 0 {
			str += fmt.Sprintf(", actions=%s", actionStr)
		}
		flows = append(flows, str)
	}

	return flows, nil
}
