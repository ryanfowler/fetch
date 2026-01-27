package grpc

import "testing"

func TestCodeString(t *testing.T) {
	tests := []struct {
		code Code
		want string
	}{
		{OK, "OK"},
		{Canceled, "CANCELED"},
		{Unknown, "UNKNOWN"},
		{InvalidArgument, "INVALID_ARGUMENT"},
		{DeadlineExceeded, "DEADLINE_EXCEEDED"},
		{NotFound, "NOT_FOUND"},
		{AlreadyExists, "ALREADY_EXISTS"},
		{PermissionDenied, "PERMISSION_DENIED"},
		{ResourceExhausted, "RESOURCE_EXHAUSTED"},
		{FailedPrecondition, "FAILED_PRECONDITION"},
		{Aborted, "ABORTED"},
		{OutOfRange, "OUT_OF_RANGE"},
		{Unimplemented, "UNIMPLEMENTED"},
		{Internal, "INTERNAL"},
		{Unavailable, "UNAVAILABLE"},
		{DataLoss, "DATA_LOSS"},
		{Unauthenticated, "UNAUTHENTICATED"},
		{Code(100), "CODE(100)"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := tt.code.String()
			if got != tt.want {
				t.Errorf("Code.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestStatusError(t *testing.T) {
	tests := []struct {
		name   string
		status *Status
		want   string
		wantOK bool
	}{
		{
			name:   "OK status",
			status: &Status{Code: OK},
			want:   "grpc error: OK",
			wantOK: true,
		},
		{
			name:   "error with message",
			status: &Status{Code: NotFound, Message: "resource not found"},
			want:   "grpc error: NOT_FOUND: resource not found",
			wantOK: false,
		},
		{
			name:   "error without message",
			status: &Status{Code: Internal},
			want:   "grpc error: INTERNAL",
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.status.Error()
			if got != tt.want {
				t.Errorf("Status.Error() = %v, want %v", got, tt.want)
			}
			if tt.status.OK() != tt.wantOK {
				t.Errorf("Status.OK() = %v, want %v", tt.status.OK(), tt.wantOK)
			}
		})
	}
}

func TestParseStatus(t *testing.T) {
	tests := []struct {
		name        string
		grpcStatus  string
		grpcMessage string
		wantCode    Code
		wantMessage string
	}{
		{
			name:        "OK",
			grpcStatus:  "0",
			grpcMessage: "",
			wantCode:    OK,
			wantMessage: "",
		},
		{
			name:        "NotFound with message",
			grpcStatus:  "5",
			grpcMessage: "not found",
			wantCode:    NotFound,
			wantMessage: "not found",
		},
		{
			name:        "invalid status string",
			grpcStatus:  "invalid",
			grpcMessage: "some message",
			wantCode:    Unknown,
			wantMessage: "some message",
		},
		{
			name:        "empty status string",
			grpcStatus:  "",
			grpcMessage: "error occurred",
			wantCode:    Unknown,
			wantMessage: "error occurred",
		},
		{
			name:        "Unauthenticated",
			grpcStatus:  "16",
			grpcMessage: "invalid token",
			wantCode:    Unauthenticated,
			wantMessage: "invalid token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := ParseStatus(tt.grpcStatus, tt.grpcMessage)
			if status.Code != tt.wantCode {
				t.Errorf("ParseStatus() Code = %v, want %v", status.Code, tt.wantCode)
			}
			if status.Message != tt.wantMessage {
				t.Errorf("ParseStatus() Message = %v, want %v", status.Message, tt.wantMessage)
			}
		})
	}
}
