package proto

import (
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"
)

// JSONToProtobuf converts JSON data to protobuf binary format.
func JSONToProtobuf(jsonData []byte, md protoreflect.MessageDescriptor) ([]byte, error) {
	msg := dynamicpb.NewMessage(md)

	// Configure unmarshaler to be lenient with field names.
	opts := protojson.UnmarshalOptions{
		DiscardUnknown: true,
	}

	if err := opts.Unmarshal(jsonData, msg); err != nil {
		return nil, err
	}

	return proto.Marshal(msg)
}

// ProtobufToJSON converts protobuf binary data to JSON format.
func ProtobufToJSON(data []byte, md protoreflect.MessageDescriptor) ([]byte, error) {
	msg := dynamicpb.NewMessage(md)

	if err := proto.Unmarshal(data, msg); err != nil {
		return nil, err
	}

	// Configure marshaler for readable output.
	opts := protojson.MarshalOptions{
		Multiline:       true,
		Indent:          "  ",
		EmitUnpopulated: false,
		UseProtoNames:   true,
	}

	return opts.Marshal(msg)
}

// ProtobufToJSONCompact converts protobuf binary data to compact JSON format.
func ProtobufToJSONCompact(data []byte, md protoreflect.MessageDescriptor) ([]byte, error) {
	msg := dynamicpb.NewMessage(md)

	if err := proto.Unmarshal(data, msg); err != nil {
		return nil, err
	}

	opts := protojson.MarshalOptions{
		Multiline:       false,
		EmitUnpopulated: false,
		UseProtoNames:   true,
	}

	return opts.Marshal(msg)
}
