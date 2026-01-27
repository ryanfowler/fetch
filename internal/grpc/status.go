package grpc

import (
	"fmt"
	"strconv"
)

// Status represents a gRPC status.
type Status struct {
	Code    Code
	Message string
}

func (s *Status) Error() string {
	if s.Message != "" {
		return fmt.Sprintf("grpc error: %s: %s", s.Code.String(), s.Message)
	}
	return fmt.Sprintf("grpc error: %s", s.Code.String())
}

// OK returns true if the status represents success.
func (s *Status) OK() bool {
	return s.Code == OK
}

// Code represents a gRPC status code.
type Code int

// gRPC status codes.
const (
	OK                 Code = 0
	Canceled           Code = 1
	Unknown            Code = 2
	InvalidArgument    Code = 3
	DeadlineExceeded   Code = 4
	NotFound           Code = 5
	AlreadyExists      Code = 6
	PermissionDenied   Code = 7
	ResourceExhausted  Code = 8
	FailedPrecondition Code = 9
	Aborted            Code = 10
	OutOfRange         Code = 11
	Unimplemented      Code = 12
	Internal           Code = 13
	Unavailable        Code = 14
	DataLoss           Code = 15
	Unauthenticated    Code = 16
)

var codeNames = map[Code]string{
	OK:                 "OK",
	Canceled:           "CANCELED",
	Unknown:            "UNKNOWN",
	InvalidArgument:    "INVALID_ARGUMENT",
	DeadlineExceeded:   "DEADLINE_EXCEEDED",
	NotFound:           "NOT_FOUND",
	AlreadyExists:      "ALREADY_EXISTS",
	PermissionDenied:   "PERMISSION_DENIED",
	ResourceExhausted:  "RESOURCE_EXHAUSTED",
	FailedPrecondition: "FAILED_PRECONDITION",
	Aborted:            "ABORTED",
	OutOfRange:         "OUT_OF_RANGE",
	Unimplemented:      "UNIMPLEMENTED",
	Internal:           "INTERNAL",
	Unavailable:        "UNAVAILABLE",
	DataLoss:           "DATA_LOSS",
	Unauthenticated:    "UNAUTHENTICATED",
}

// String returns the name of the status code.
func (c Code) String() string {
	if name, ok := codeNames[c]; ok {
		return name
	}
	return fmt.Sprintf("CODE(%d)", c)
}

// ParseStatus parses gRPC status from HTTP trailers.
func ParseStatus(grpcStatus, grpcMessage string) *Status {
	code := Unknown
	if grpcStatus != "" {
		if n, err := strconv.Atoi(grpcStatus); err == nil {
			code = Code(n)
		}
	}
	return &Status{Code: code, Message: grpcMessage}
}
