package gcs

import (
	"encoding/json"
	"fmt"

	"github.com/Microsoft/go-winio/pkg/guid"
	"github.com/Microsoft/hcsshim/internal/schema1"
	hcsschema "github.com/Microsoft/hcsshim/internal/schema2"
)

// LinuxGcsVsockPort is the vsock port number that the Linux GCS will
// connect to.
const LinuxGcsVsockPort = 0x40000000

// WindowsGcsHvsockServiceID is the hvsock service ID that the Windows GCS
// will connect to.
var WindowsGcsHvsockServiceID = guid.GUID{
	Data1: 0xacef5661,
	Data2: 0x84a1,
	Data3: 0x4e44,
	Data4: [8]uint8{0x85, 0x6b, 0x62, 0x45, 0xe6, 0x9f, 0x46, 0x20},
}

type anyInString struct {
	Value interface{}
}

func (a *anyInString) MarshalText() ([]byte, error) {
	return json.Marshal(a.Value)
}

func (a *anyInString) UnmarshalText(b []byte) error {
	return json.Unmarshal(b, &a.Value)
}

type rpcProc uint32

const (
	rpcCreate rpcProc = (iota+1)<<8 | 1
	rpcStart
	rpcShutdownGraceful
	rpcShutdownForced
	rpcExecuteProcess
	rpcWaitForProcess
	rpcSignalProcess
	rpcResizeConsole
	rpcGetProperties
	rpcModifySettings
	rpcNegotiateProtocol
	rpcDumpStacks
	rpcLifecycleNotification
)

type msgType uint32

const (
	msgTypeRequest  msgType = 0x10100000
	msgTypeResponse         = 0x20100000
	msgTypeNotify           = 0x30100000
	msgTypeMask             = 0xfff00000

	notifyContainer = 1<<8 | 1
)

func (typ msgType) String() string {
	var s string
	switch typ & msgTypeMask {
	case msgTypeRequest:
		s = "Request("
	case msgTypeResponse:
		s = "Response("
	case msgTypeNotify:
		s = "Notify("
		switch typ - msgTypeNotify {
		case notifyContainer:
			s += "Container"
		default:
			s += fmt.Sprintf("%#x", uint32(typ))
		}
		return s + ")"
	default:
		return fmt.Sprintf("%#x", uint32(typ))
	}
	switch rpcProc(typ &^ msgTypeMask) {
	case rpcCreate:
		s += "Create"
	case rpcStart:
		s += "Start"
	case rpcShutdownGraceful:
		s += "ShutdownGraceful"
	case rpcShutdownForced:
		s += "ShutdownForced"
	case rpcExecuteProcess:
		s += "ExecuteProcess"
	case rpcWaitForProcess:
		s += "WaitForProcess"
	case rpcSignalProcess:
		s += "SignalProcess"
	case rpcResizeConsole:
		s += "ResizeConsole"
	case rpcGetProperties:
		s += "GetProperties"
	case rpcModifySettings:
		s += "ModifySettings"
	case rpcNegotiateProtocol:
		s += "NegotiateProtocol"
	case rpcDumpStacks:
		s += "DumpStacks"
	case rpcLifecycleNotification:
		s += "LifecycleNotification"
	default:
		s += fmt.Sprintf("%#x", uint32(typ))
	}
	return s + ")"
}

// ocspancontext is the internal JSON representation of the OpenCensus
// `trace.SpanContext` for fowarding to a GCS that supports it.
type ocspancontext struct {
	// TraceID is the `hex` encoded string of the OpenCensus
	// `SpanContext.TraceID` to propagate to the guest.
	TraceID string `json:",omitempty"`
	// SpanID is the `hex` encoded string of the OpenCensus `SpanContext.SpanID`
	// to propagate to the guest.
	SpanID string `json:",omitempty"`

	// TraceOptions is the OpenCensus `SpanContext.TraceOptions` passed through
	// to propagate to the guest.
	TraceOptions uint32 `json:",omitempty"`

	// Tracestate is the `base64` encoded string of marshaling the OpenCensus
	// `SpanContext.TraceState.Entries()` to JSON.
	//
	// If `SpanContext.Tracestate == nil ||
	// len(SpanContext.Tracestate.Entries()) == 0` this will be `""`.
	Tracestate string `json:",omitempty"`
}

type requestBase struct {
	ContainerID string    `json:"ContainerId"`
	ActivityID  guid.GUID `json:"ActivityId"`

	// OpenCensusSpanContext is the encoded OpenCensus `trace.SpanContext` if
	// set when making the request.
	//
	// NOTE: This is not a part of the protocol but because its a JSON protocol
	// adding fields is a non-breaking change. If the guest supports it this is
	// just additive context.
	OpenCensusSpanContext *ocspancontext `json:"ocsc,omitempty"`
}

func (req *requestBase) Base() *requestBase {
	return req
}

type responseBase struct {
	Result       int32         // HResult
	ErrorMessage string        `json:",omitempty"`
	ActivityID   guid.GUID     `json:"ActivityId,omitempty"`
	ErrorRecords []errorRecord `json:",omitempty"`
}

type errorRecord struct {
	Result       int32 // HResult
	Message      string
	StackTrace   string `json:",omitempty"`
	ModuleName   string
	FileName     string
	Line         uint32
	FunctionName string `json:",omitempty"`
}

func (resp *responseBase) Base() *responseBase {
	return resp
}

type negotiateProtocolRequest struct {
	requestBase
	MinimumVersion uint32
	MaximumVersion uint32
}

type negotiateProtocolResponse struct {
	responseBase
	Version      uint32          `json:",omitempty"`
	Capabilities gcsCapabilities `json:",omitempty"`
}

type dumpStacksRequest struct {
	requestBase
}

type dumpStacksResponse struct {
	responseBase
	GuestStacks string
}

type containerCreate struct {
	requestBase
	ContainerConfig anyInString
}

type uvmConfig struct {
	SystemType string // must be "Container"
}

type containerNotification struct {
	requestBase
	Type       string      // Compute.System.NotificationType
	Operation  string      // Compute.System.ActiveOperation
	Result     int32       // HResult
	ResultInfo anyInString `json:",omitempty"`
}

type containerExecuteProcess struct {
	requestBase
	Settings executeProcessSettings
}

type executeProcessSettings struct {
	ProcessParameters       anyInString
	StdioRelaySettings      *executeProcessStdioRelaySettings      `json:",omitempty"`
	VsockStdioRelaySettings *executeProcessVsockStdioRelaySettings `json:",omitempty"`
}

type executeProcessStdioRelaySettings struct {
	StdIn  *guid.GUID `json:",omitempty"`
	StdOut *guid.GUID `json:",omitempty"`
	StdErr *guid.GUID `json:",omitempty"`
}

type executeProcessVsockStdioRelaySettings struct {
	StdIn  uint32 `json:",omitempty"`
	StdOut uint32 `json:",omitempty"`
	StdErr uint32 `json:",omitempty"`
}

type containerResizeConsole struct {
	requestBase
	ProcessID uint32 `json:"ProcessId"`
	Height    uint16
	Width     uint16
}

type containerWaitForProcess struct {
	requestBase
	ProcessID   uint32 `json:"ProcessId"`
	TimeoutInMs uint32
}

type containerSignalProcess struct {
	requestBase
	ProcessID uint32      `json:"ProcessId"`
	Options   interface{} `json:",omitempty"`
}

type containerPropertiesQuery schema1.PropertyQuery

func (q *containerPropertiesQuery) MarshalText() ([]byte, error) {
	return json.Marshal((*schema1.PropertyQuery)(q))
}

func (q *containerPropertiesQuery) UnmarshalText(b []byte) error {
	return json.Unmarshal(b, (*schema1.PropertyQuery)(q))
}

type containerGetProperties struct {
	requestBase
	Query containerPropertiesQuery
}

type containerModifySettings struct {
	requestBase
	Request interface{}
}

type gcsCapabilities struct {
	SendHostCreateMessage      bool
	SendHostStartMessage       bool
	HvSocketConfigOnStartup    bool
	SendLifecycleNotifications bool
	SupportedSchemaVersions    []hcsschema.Version
	RuntimeOsType              string
	GuestDefinedCapabilities   interface{}
}

type containerCreateResponse struct {
	responseBase
}

type containerExecuteProcessResponse struct {
	responseBase
	ProcessID uint32 `json:"ProcessId"`
}

type containerWaitForProcessResponse struct {
	responseBase
	ExitCode uint32
}

type containerProperties schema1.ContainerProperties

func (p *containerProperties) MarshalText() ([]byte, error) {
	return json.Marshal((*schema1.ContainerProperties)(p))
}

func (p *containerProperties) UnmarshalText(b []byte) error {
	return json.Unmarshal(b, (*schema1.ContainerProperties)(p))
}

type containerGetPropertiesResponse struct {
	responseBase
	Properties containerProperties
}
