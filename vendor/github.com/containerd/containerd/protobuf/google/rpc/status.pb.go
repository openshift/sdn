// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: github.com/containerd/containerd/protobuf/google/rpc/status.proto

package rpc

import proto "github.com/gogo/protobuf/proto"
import fmt "fmt"
import math "math"
import google_protobuf1 "github.com/gogo/protobuf/types"

import strings "strings"
import reflect "reflect"

import io "io"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// The `Status` type defines a logical error model that is suitable for different
// programming environments, including REST APIs and RPC APIs. It is used by
// [gRPC](https://github.com/grpc). The error model is designed to be:
//
// - Simple to use and understand for most users
// - Flexible enough to meet unexpected needs
//
// # Overview
//
// The `Status` message contains three pieces of data: error code, error message,
// and error details. The error code should be an enum value of
// [google.rpc.Code][google.rpc.Code], but it may accept additional error codes if needed.  The
// error message should be a developer-facing English message that helps
// developers *understand* and *resolve* the error. If a localized user-facing
// error message is needed, put the localized message in the error details or
// localize it in the client. The optional error details may contain arbitrary
// information about the error. There is a predefined set of error detail types
// in the package `google.rpc` that can be used for common error conditions.
//
// # Language mapping
//
// The `Status` message is the logical representation of the error model, but it
// is not necessarily the actual wire format. When the `Status` message is
// exposed in different client libraries and different wire protocols, it can be
// mapped differently. For example, it will likely be mapped to some exceptions
// in Java, but more likely mapped to some error codes in C.
//
// # Other uses
//
// The error model and the `Status` message can be used in a variety of
// environments, either with or without APIs, to provide a
// consistent developer experience across different environments.
//
// Example uses of this error model include:
//
// - Partial errors. If a service needs to return partial errors to the client,
//     it may embed the `Status` in the normal response to indicate the partial
//     errors.
//
// - Workflow errors. A typical workflow has multiple steps. Each step may
//     have a `Status` message for error reporting.
//
// - Batch operations. If a client uses batch request and batch response, the
//     `Status` message should be used directly inside batch response, one for
//     each error sub-response.
//
// - Asynchronous operations. If an API call embeds asynchronous operation
//     results in its response, the status of those operations should be
//     represented directly using the `Status` message.
//
// - Logging. If some API errors are stored in logs, the message `Status` could
//     be used directly after any stripping needed for security/privacy reasons.
type Status struct {
	// The status code, which should be an enum value of [google.rpc.Code][google.rpc.Code].
	Code int32 `protobuf:"varint,1,opt,name=code,proto3" json:"code,omitempty"`
	// A developer-facing error message, which should be in English. Any
	// user-facing error message should be localized and sent in the
	// [google.rpc.Status.details][google.rpc.Status.details] field, or localized by the client.
	Message string `protobuf:"bytes,2,opt,name=message,proto3" json:"message,omitempty"`
	// A list of messages that carry the error details.  There is a common set of
	// message types for APIs to use.
	Details []*google_protobuf1.Any `protobuf:"bytes,3,rep,name=details" json:"details,omitempty"`
}

func (m *Status) Reset()                    { *m = Status{} }
func (*Status) ProtoMessage()               {}
func (*Status) Descriptor() ([]byte, []int) { return fileDescriptorStatus, []int{0} }

func init() {
	proto.RegisterType((*Status)(nil), "google.rpc.Status")
}
func (m *Status) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *Status) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if m.Code != 0 {
		dAtA[i] = 0x8
		i++
		i = encodeVarintStatus(dAtA, i, uint64(m.Code))
	}
	if len(m.Message) > 0 {
		dAtA[i] = 0x12
		i++
		i = encodeVarintStatus(dAtA, i, uint64(len(m.Message)))
		i += copy(dAtA[i:], m.Message)
	}
	if len(m.Details) > 0 {
		for _, msg := range m.Details {
			dAtA[i] = 0x1a
			i++
			i = encodeVarintStatus(dAtA, i, uint64(msg.Size()))
			n, err := msg.MarshalTo(dAtA[i:])
			if err != nil {
				return 0, err
			}
			i += n
		}
	}
	return i, nil
}

func encodeVarintStatus(dAtA []byte, offset int, v uint64) int {
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return offset + 1
}
func (m *Status) Size() (n int) {
	var l int
	_ = l
	if m.Code != 0 {
		n += 1 + sovStatus(uint64(m.Code))
	}
	l = len(m.Message)
	if l > 0 {
		n += 1 + l + sovStatus(uint64(l))
	}
	if len(m.Details) > 0 {
		for _, e := range m.Details {
			l = e.Size()
			n += 1 + l + sovStatus(uint64(l))
		}
	}
	return n
}

func sovStatus(x uint64) (n int) {
	for {
		n++
		x >>= 7
		if x == 0 {
			break
		}
	}
	return n
}
func sozStatus(x uint64) (n int) {
	return sovStatus(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (this *Status) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&Status{`,
		`Code:` + fmt.Sprintf("%v", this.Code) + `,`,
		`Message:` + fmt.Sprintf("%v", this.Message) + `,`,
		`Details:` + strings.Replace(fmt.Sprintf("%v", this.Details), "Any", "google_protobuf1.Any", 1) + `,`,
		`}`,
	}, "")
	return s
}
func valueToStringStatus(v interface{}) string {
	rv := reflect.ValueOf(v)
	if rv.IsNil() {
		return "nil"
	}
	pv := reflect.Indirect(rv).Interface()
	return fmt.Sprintf("*%v", pv)
}
func (m *Status) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowStatus
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: Status: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Status: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Code", wireType)
			}
			m.Code = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowStatus
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Code |= (int32(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Message", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowStatus
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthStatus
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Message = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Details", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowStatus
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthStatus
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Details = append(m.Details, &google_protobuf1.Any{})
			if err := m.Details[len(m.Details)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipStatus(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthStatus
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipStatus(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowStatus
			}
			if iNdEx >= l {
				return 0, io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		wireType := int(wire & 0x7)
		switch wireType {
		case 0:
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowStatus
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
			return iNdEx, nil
		case 1:
			iNdEx += 8
			return iNdEx, nil
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowStatus
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				length |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			iNdEx += length
			if length < 0 {
				return 0, ErrInvalidLengthStatus
			}
			return iNdEx, nil
		case 3:
			for {
				var innerWire uint64
				var start int = iNdEx
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return 0, ErrIntOverflowStatus
					}
					if iNdEx >= l {
						return 0, io.ErrUnexpectedEOF
					}
					b := dAtA[iNdEx]
					iNdEx++
					innerWire |= (uint64(b) & 0x7F) << shift
					if b < 0x80 {
						break
					}
				}
				innerWireType := int(innerWire & 0x7)
				if innerWireType == 4 {
					break
				}
				next, err := skipStatus(dAtA[start:])
				if err != nil {
					return 0, err
				}
				iNdEx = start + next
			}
			return iNdEx, nil
		case 4:
			return iNdEx, nil
		case 5:
			iNdEx += 4
			return iNdEx, nil
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
	}
	panic("unreachable")
}

var (
	ErrInvalidLengthStatus = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowStatus   = fmt.Errorf("proto: integer overflow")
)

func init() {
	proto.RegisterFile("github.com/containerd/containerd/protobuf/google/rpc/status.proto", fileDescriptorStatus)
}

var fileDescriptorStatus = []byte{
	// 236 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0x72, 0x4c, 0xcf, 0x2c, 0xc9,
	0x28, 0x4d, 0xd2, 0x4b, 0xce, 0xcf, 0xd5, 0x4f, 0xce, 0xcf, 0x2b, 0x49, 0xcc, 0xcc, 0x4b, 0x2d,
	0x4a, 0x41, 0x66, 0x16, 0x14, 0xe5, 0x97, 0xe4, 0x27, 0x95, 0xa6, 0xe9, 0xa7, 0xe7, 0xe7, 0xa7,
	0xe7, 0xa4, 0xea, 0x17, 0x15, 0x24, 0xeb, 0x17, 0x97, 0x24, 0x96, 0x94, 0x16, 0xeb, 0x81, 0xa5,
	0x84, 0xb8, 0x20, 0x12, 0x7a, 0x45, 0x05, 0xc9, 0x52, 0x92, 0x50, 0x45, 0x70, 0x4d, 0x89, 0x79,
	0x95, 0x10, 0x65, 0x4a, 0x69, 0x5c, 0x6c, 0xc1, 0x60, 0x6d, 0x42, 0x42, 0x5c, 0x2c, 0xc9, 0xf9,
	0x29, 0xa9, 0x12, 0x8c, 0x0a, 0x8c, 0x1a, 0xac, 0x41, 0x60, 0xb6, 0x90, 0x04, 0x17, 0x7b, 0x6e,
	0x6a, 0x71, 0x71, 0x62, 0x7a, 0xaa, 0x04, 0x93, 0x02, 0xa3, 0x06, 0x67, 0x10, 0x8c, 0x2b, 0xa4,
	0xc7, 0xc5, 0x9e, 0x92, 0x5a, 0x92, 0x98, 0x99, 0x53, 0x2c, 0xc1, 0xac, 0xc0, 0xac, 0xc1, 0x6d,
	0x24, 0xa2, 0x07, 0xb5, 0x10, 0x66, 0x89, 0x9e, 0x63, 0x5e, 0x65, 0x10, 0x4c, 0x91, 0x53, 0xf9,
	0x89, 0x87, 0x72, 0x0c, 0x37, 0x1e, 0xca, 0x31, 0x34, 0x3c, 0x92, 0x63, 0x3c, 0xf1, 0x48, 0x8e,
	0xf1, 0xc2, 0x23, 0x39, 0xc6, 0x07, 0x8f, 0xe4, 0x18, 0xb9, 0xf8, 0x92, 0xf3, 0x73, 0xf5, 0x10,
	0x8e, 0x75, 0xe2, 0x86, 0xb8, 0x27, 0x00, 0x64, 0x4c, 0x00, 0x63, 0x94, 0x05, 0x39, 0x41, 0x61,
	0x5d, 0x54, 0x90, 0xbc, 0x88, 0x89, 0x39, 0x28, 0xc0, 0x39, 0x89, 0x0d, 0x2c, 0x6d, 0x0c, 0x08,
	0x00, 0x00, 0xff, 0xff, 0x7d, 0xb3, 0x06, 0x51, 0x53, 0x01, 0x00, 0x00,
}
