package proto

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/ryanfowler/fetch/internal/core"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"
)

var errDescriptorSetNotRegular = errors.New("descriptor set file is not a regular file")

// LoadDescriptorSetFile loads a schema from a pre-compiled FileDescriptorSet file (.pb).
func LoadDescriptorSetFile(path string) (*Schema, error) {
	return LoadDescriptorSetFileWithContext(context.Background(), path)
}

// LoadDescriptorSetFileWithContext loads a schema from a pre-compiled
// FileDescriptorSet file (.pb), honoring ctx while reading the file.
func LoadDescriptorSetFileWithContext(ctx context.Context, path string) (*Schema, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, descriptorReadError(err)
	}

	// Open and validate the same file handle. Platform-specific opening avoids
	// blocking on a replaced FIFO or device before the regular-file check.
	file, info, err := openDescriptorSetFile(path)
	if err != nil {
		return nil, descriptorReadError(err)
	}
	defer file.Close()
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, descriptorReadError(ctxErr)
	}

	// Check the reported size before allocating. ReadAllLimited below still
	// handles a file that grows after this check.
	if info.Size() > core.MaxProtobufDescriptorSetBytes {
		return nil, descriptorReadError(core.LimitError{
			Subsystem: "protobuf descriptor set",
			Limit:     core.MaxProtobufDescriptorSetBytes,
		})
	}

	data, err := readDescriptorSetFile(ctx, file)
	if err != nil {
		return nil, descriptorReadError(err)
	}

	return loadDescriptorSetBytes(data)
}

func descriptorReadError(err error) error {
	return fmt.Errorf("failed to read descriptor set file: %w", err)
}

func readDescriptorSetFile(ctx context.Context, file *os.File) ([]byte, error) {
	stopClose := context.AfterFunc(ctx, func() {
		_ = file.Close()
	})
	defer stopClose()

	data, err := core.ReadAllLimited(contextReader{ctx: ctx, reader: file}, core.MaxProtobufDescriptorSetBytes, "protobuf descriptor set")
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}
	return data, err
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	select {
	case <-r.ctx.Done():
		return 0, r.ctx.Err()
	default:
	}

	n, err := r.reader.Read(p)
	if ctxErr := r.ctx.Err(); ctxErr != nil {
		return n, ctxErr
	}
	return n, err
}

// loadDescriptorSetBytes loads a schema from FileDescriptorSet bytes.
func loadDescriptorSetBytes(data []byte) (*Schema, error) {
	if int64(len(data)) > core.MaxProtobufDescriptorSetBytes {
		return nil, fmt.Errorf("failed to unmarshal FileDescriptorSet: %w", core.LimitError{
			Subsystem: "protobuf descriptor set",
			Limit:     core.MaxProtobufDescriptorSetBytes,
		})
	}
	fds := &descriptorpb.FileDescriptorSet{}
	if err := proto.Unmarshal(data, fds); err != nil {
		return nil, fmt.Errorf("failed to unmarshal FileDescriptorSet: %w", err)
	}

	return LoadFromDescriptorSet(fds)
}
