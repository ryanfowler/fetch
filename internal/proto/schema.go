package proto

import (
	"fmt"
	"sort"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
)

// Schema holds loaded protobuf type information from descriptors.
type Schema struct {
	files    *protoregistry.Files
	messages map[string]protoreflect.MessageDescriptor
	services map[string]protoreflect.ServiceDescriptor
}

// NewSchema creates an empty schema.
func NewSchema() *Schema {
	return &Schema{
		files:    new(protoregistry.Files),
		messages: make(map[string]protoreflect.MessageDescriptor),
		services: make(map[string]protoreflect.ServiceDescriptor),
	}
}

// LoadFromDescriptorSet loads schema from a FileDescriptorSet.
func LoadFromDescriptorSet(fds *descriptorpb.FileDescriptorSet) (*Schema, error) {
	if err := validateDescriptorSet(fds); err != nil {
		return nil, err
	}
	schema := NewSchema()

	// Build file descriptors.
	files, err := protodesc.NewFiles(fds)
	if err != nil {
		return nil, fmt.Errorf("failed to create file descriptors: %w", err)
	}
	schema.files = files

	// Index all messages and services.
	files.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		schema.indexFile(fd)
		return true
	})

	return schema, nil
}

// validateDescriptorSet performs deterministic checks before protodesc.NewFiles
// builds its resolver. NewFiles can discover several invalid dependency graphs
// through map-backed registries, which otherwise makes the first reported error
// depend on iteration order.
func validateDescriptorSet(fds *descriptorpb.FileDescriptorSet) error {
	if fds == nil {
		return fmt.Errorf("descriptor set is nil")
	}

	files := make(map[string]*descriptorpb.FileDescriptorProto, len(fds.File))
	for i, fd := range fds.File {
		if fd == nil || fd.GetName() == "" {
			return fmt.Errorf("descriptor file %d is missing a file name", i)
		}
		name := fd.GetName()
		if existing, ok := files[name]; ok {
			if !proto.Equal(existing, fd) {
				return fmt.Errorf("descriptor file %q has inconsistent definitions", name)
			}
			return fmt.Errorf("descriptor file %q is duplicated", name)
		}
		files[name] = fd
	}

	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	state := make(map[string]uint8, len(files))
	var visit func(string) error
	visit = func(name string) error {
		switch state[name] {
		case 1:
			return fmt.Errorf("descriptor dependency cycle includes %q", name)
		case 2:
			return nil
		}
		state[name] = 1
		dependencies := append([]string(nil), files[name].Dependency...)
		sort.Strings(dependencies)
		for _, dependency := range dependencies {
			if _, ok := files[dependency]; ok {
				if err := visit(dependency); err != nil {
					return err
				}
				continue
			}
			if _, err := protoregistry.GlobalFiles.FindFileByPath(dependency); err != nil {
				return fmt.Errorf("descriptor %q depends on missing file %q", name, dependency)
			}
		}
		state[name] = 2
		return nil
	}
	for _, name := range names {
		if err := visit(name); err != nil {
			return err
		}
	}
	return nil
}

// indexFile indexes all messages and services in a file descriptor.
func (s *Schema) indexFile(fd protoreflect.FileDescriptor) {
	// Index top-level messages.
	msgs := fd.Messages()
	for i := 0; i < msgs.Len(); i++ {
		s.indexMessage(msgs.Get(i))
	}

	// Index services.
	svcs := fd.Services()
	for i := 0; i < svcs.Len(); i++ {
		svc := svcs.Get(i)
		s.services[string(svc.FullName())] = svc
	}
}

// indexMessage indexes a message and its nested messages.
func (s *Schema) indexMessage(md protoreflect.MessageDescriptor) {
	s.messages[string(md.FullName())] = md

	// Index nested messages.
	nested := md.Messages()
	for i := 0; i < nested.Len(); i++ {
		s.indexMessage(nested.Get(i))
	}
}

// FindMessage finds a message descriptor by full name.
// The name can be with or without leading dot.
func (s *Schema) FindMessage(name string) (protoreflect.MessageDescriptor, error) {
	name = strings.TrimPrefix(name, ".")

	if md, ok := s.messages[name]; ok {
		return md, nil
	}
	return nil, fmt.Errorf("message type not found: %s", name)
}

// FindService finds a service descriptor by full name.
func (s *Schema) FindService(name string) (protoreflect.ServiceDescriptor, error) {
	name = strings.TrimPrefix(name, ".")

	if sd, ok := s.services[name]; ok {
		return sd, nil
	}
	return nil, fmt.Errorf("service not found: %s", name)
}

// FindMethod finds a method in a service by service and method name.
// The format can be "package.Service/Method" or "package.Service.Method".
func (s *Schema) FindMethod(fullName string) (protoreflect.MethodDescriptor, error) {
	// Try both "/" and "." as separators.
	var serviceName, methodName string
	if idx := strings.LastIndex(fullName, "/"); idx >= 0 {
		serviceName = fullName[:idx]
		methodName = fullName[idx+1:]
	} else if idx := strings.LastIndex(fullName, "."); idx >= 0 {
		serviceName = fullName[:idx]
		methodName = fullName[idx+1:]
	} else {
		return nil, fmt.Errorf("invalid method name format: %s (expected 'Service/Method' or 'Service.Method')", fullName)
	}

	sd, err := s.FindService(serviceName)
	if err != nil {
		return nil, err
	}

	methods := sd.Methods()
	for i := 0; i < methods.Len(); i++ {
		m := methods.Get(i)
		if string(m.Name()) == methodName {
			return m, nil
		}
	}

	return nil, fmt.Errorf("method %s not found in service %s", methodName, serviceName)
}

// ListMessages returns all message type names.
func (s *Schema) ListMessages() []string {
	names := make([]string, 0, len(s.messages))
	for name := range s.messages {
		names = append(names, name)
	}
	return names
}

// ListServices returns all service names.
func (s *Schema) ListServices() []string {
	names := make([]string, 0, len(s.services))
	for name := range s.services {
		names = append(names, name)
	}
	return names
}
