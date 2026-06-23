mod convert;
mod descriptor_wire;
mod discovery;
mod json_stream;
mod schema;

pub(crate) use convert::grpc_request_body;
pub use convert::{json_to_protobuf, protobuf_to_json, protobuf_to_json_compact};
pub use discovery::{describe_symbol, execute_local_discovery};
#[cfg(test)]
pub(crate) use json_stream::json_reader_to_grpc_frame_stream_with_limit;
pub use json_stream::stream_json_to_grpc_frames;
pub(crate) use json_stream::{json_reader_to_grpc_frame_stream, stdin_json_to_grpc_frame_stream};
pub use schema::{
    Schema, compile_protos, load_local_schema, method_for_url, normalize_symbol_name,
    proto_file_paths,
};

#[derive(Debug, thiserror::Error)]
pub enum ProtoError {
    #[error("{0}")]
    Message(String),
    #[error(
        "protoc not found in PATH. Install protoc from https://github.com/protocolbuffers/protobuf/releases"
    )]
    ProtocNotFound,
    #[error("protoc failed: {0}")]
    Protoc(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grpc::framing;
    use futures_util::TryStreamExt;
    use prost::Message;
    use prost_reflect::MessageDescriptor;
    use prost_types::{
        DescriptorProto, EnumDescriptorProto, EnumValueDescriptorProto, FieldDescriptorProto,
        FileDescriptorProto, FileDescriptorSet, MessageOptions, MethodDescriptorProto,
        OneofDescriptorProto, ServiceDescriptorProto,
        field_descriptor_proto::{Label, Type},
    };
    use std::path::Path;

    fn stream_descriptor_set() -> Vec<u8> {
        let fds = FileDescriptorSet {
            file: vec![FileDescriptorProto {
                name: Some("stream.proto".to_string()),
                package: Some("streampkg".to_string()),
                syntax: Some("proto3".to_string()),
                message_type: vec![
                    DescriptorProto {
                        name: Some("StreamRequest".to_string()),
                        field: vec![FieldDescriptorProto {
                            name: Some("value".to_string()),
                            number: Some(1),
                            label: Some(Label::Optional as i32),
                            r#type: Some(Type::String as i32),
                            ..Default::default()
                        }],
                        ..Default::default()
                    },
                    DescriptorProto {
                        name: Some("StreamResponse".to_string()),
                        field: vec![FieldDescriptorProto {
                            name: Some("count".to_string()),
                            number: Some(1),
                            label: Some(Label::Optional as i32),
                            r#type: Some(Type::Int64 as i32),
                            ..Default::default()
                        }],
                        ..Default::default()
                    },
                ],
                service: vec![ServiceDescriptorProto {
                    name: Some("StreamService".to_string()),
                    method: vec![MethodDescriptorProto {
                        name: Some("ClientStream".to_string()),
                        input_type: Some(".streampkg.StreamRequest".to_string()),
                        output_type: Some(".streampkg.StreamResponse".to_string()),
                        client_streaming: Some(true),
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        };
        fds.encode_to_vec()
    }

    fn test_descriptor_set() -> Vec<u8> {
        let fds = FileDescriptorSet {
            file: vec![FileDescriptorProto {
                name: Some("test.proto".to_string()),
                package: Some("testpkg".to_string()),
                syntax: Some("proto3".to_string()),
                message_type: vec![
                    DescriptorProto {
                        name: Some("TestMessage".to_string()),
                        field: vec![
                            FieldDescriptorProto {
                                name: Some("id".to_string()),
                                number: Some(1),
                                label: Some(Label::Optional as i32),
                                r#type: Some(Type::Int64 as i32),
                                ..Default::default()
                            },
                            FieldDescriptorProto {
                                name: Some("name".to_string()),
                                number: Some(2),
                                label: Some(Label::Optional as i32),
                                r#type: Some(Type::String as i32),
                                ..Default::default()
                            },
                        ],
                        ..Default::default()
                    },
                    DescriptorProto {
                        name: Some("NestedOuter".to_string()),
                        nested_type: vec![DescriptorProto {
                            name: Some("NestedInner".to_string()),
                            field: vec![FieldDescriptorProto {
                                name: Some("value".to_string()),
                                number: Some(1),
                                label: Some(Label::Optional as i32),
                                r#type: Some(Type::String as i32),
                                ..Default::default()
                            }],
                            ..Default::default()
                        }],
                        ..Default::default()
                    },
                ],
                service: vec![ServiceDescriptorProto {
                    name: Some("TestService".to_string()),
                    method: vec![
                        MethodDescriptorProto {
                            name: Some("GetTest".to_string()),
                            input_type: Some(".testpkg.TestMessage".to_string()),
                            output_type: Some(".testpkg.TestMessage".to_string()),
                            ..Default::default()
                        },
                        MethodDescriptorProto {
                            name: Some("CreateTest".to_string()),
                            input_type: Some(".testpkg.TestMessage".to_string()),
                            output_type: Some(".testpkg.TestMessage".to_string()),
                            ..Default::default()
                        },
                    ],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        };
        fds.encode_to_vec()
    }

    fn nested_descriptor_set() -> Vec<u8> {
        let fds = FileDescriptorSet {
            file: vec![FileDescriptorProto {
                name: Some("nested.proto".to_string()),
                package: Some("nested".to_string()),
                syntax: Some("proto3".to_string()),
                message_type: vec![
                    DescriptorProto {
                        name: Some("Inner".to_string()),
                        field: vec![FieldDescriptorProto {
                            name: Some("value".to_string()),
                            number: Some(1),
                            label: Some(Label::Optional as i32),
                            r#type: Some(Type::String as i32),
                            ..Default::default()
                        }],
                        ..Default::default()
                    },
                    DescriptorProto {
                        name: Some("Outer".to_string()),
                        field: vec![
                            FieldDescriptorProto {
                                name: Some("inner".to_string()),
                                number: Some(1),
                                label: Some(Label::Optional as i32),
                                r#type: Some(Type::Message as i32),
                                type_name: Some(".nested.Inner".to_string()),
                                ..Default::default()
                            },
                            FieldDescriptorProto {
                                name: Some("count".to_string()),
                                number: Some(2),
                                label: Some(Label::Optional as i32),
                                r#type: Some(Type::Int32 as i32),
                                ..Default::default()
                            },
                        ],
                        ..Default::default()
                    },
                ],
                ..Default::default()
            }],
        };
        fds.encode_to_vec()
    }

    fn edge_descriptor_set() -> Vec<u8> {
        let fds = FileDescriptorSet {
            file: vec![FileDescriptorProto {
                name: Some("edge.proto".to_string()),
                package: Some("edgepkg".to_string()),
                syntax: Some("proto3".to_string()),
                enum_type: vec![EnumDescriptorProto {
                    name: Some("State".to_string()),
                    value: vec![
                        EnumValueDescriptorProto {
                            name: Some("STATE_UNKNOWN".to_string()),
                            number: Some(0),
                            ..Default::default()
                        },
                        EnumValueDescriptorProto {
                            name: Some("STATE_READY".to_string()),
                            number: Some(1),
                            ..Default::default()
                        },
                    ],
                    ..Default::default()
                }],
                message_type: vec![
                    DescriptorProto {
                        name: Some("LabelsEntry".to_string()),
                        field: vec![
                            FieldDescriptorProto {
                                name: Some("key".to_string()),
                                number: Some(1),
                                label: Some(Label::Optional as i32),
                                r#type: Some(Type::String as i32),
                                ..Default::default()
                            },
                            FieldDescriptorProto {
                                name: Some("value".to_string()),
                                number: Some(2),
                                label: Some(Label::Optional as i32),
                                r#type: Some(Type::Int32 as i32),
                                ..Default::default()
                            },
                        ],
                        options: Some(MessageOptions {
                            map_entry: Some(true),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    DescriptorProto {
                        name: Some("EdgeMessage".to_string()),
                        field: vec![
                            FieldDescriptorProto {
                                name: Some("flag".to_string()),
                                number: Some(1),
                                label: Some(Label::Optional as i32),
                                r#type: Some(Type::Bool as i32),
                                ..Default::default()
                            },
                            FieldDescriptorProto {
                                name: Some("blob".to_string()),
                                number: Some(2),
                                label: Some(Label::Optional as i32),
                                r#type: Some(Type::Bytes as i32),
                                ..Default::default()
                            },
                            FieldDescriptorProto {
                                name: Some("state".to_string()),
                                number: Some(3),
                                label: Some(Label::Optional as i32),
                                r#type: Some(Type::Enum as i32),
                                type_name: Some(".edgepkg.State".to_string()),
                                ..Default::default()
                            },
                            FieldDescriptorProto {
                                name: Some("scores".to_string()),
                                number: Some(4),
                                label: Some(Label::Repeated as i32),
                                r#type: Some(Type::Sint32 as i32),
                                ..Default::default()
                            },
                            FieldDescriptorProto {
                                name: Some("labels".to_string()),
                                number: Some(5),
                                label: Some(Label::Repeated as i32),
                                r#type: Some(Type::Message as i32),
                                type_name: Some(".edgepkg.LabelsEntry".to_string()),
                                ..Default::default()
                            },
                            FieldDescriptorProto {
                                name: Some("choice_text".to_string()),
                                number: Some(6),
                                label: Some(Label::Optional as i32),
                                r#type: Some(Type::String as i32),
                                oneof_index: Some(0),
                                ..Default::default()
                            },
                            FieldDescriptorProto {
                                name: Some("choice_count".to_string()),
                                number: Some(7),
                                label: Some(Label::Optional as i32),
                                r#type: Some(Type::Int64 as i32),
                                oneof_index: Some(0),
                                ..Default::default()
                            },
                            FieldDescriptorProto {
                                name: Some("maybe".to_string()),
                                number: Some(8),
                                label: Some(Label::Optional as i32),
                                r#type: Some(Type::String as i32),
                                proto3_optional: Some(true),
                                oneof_index: Some(1),
                                ..Default::default()
                            },
                        ],
                        oneof_decl: vec![
                            OneofDescriptorProto {
                                name: Some("choice".to_string()),
                                ..Default::default()
                            },
                            OneofDescriptorProto {
                                name: Some("_maybe".to_string()),
                                ..Default::default()
                            },
                        ],
                        ..Default::default()
                    },
                ],
                service: vec![ServiceDescriptorProto {
                    name: Some("EdgeService".to_string()),
                    method: vec![
                        MethodDescriptorProto {
                            name: Some("ServerStream".to_string()),
                            input_type: Some(".edgepkg.EdgeMessage".to_string()),
                            output_type: Some(".edgepkg.EdgeMessage".to_string()),
                            server_streaming: Some(true),
                            ..Default::default()
                        },
                        MethodDescriptorProto {
                            name: Some("Bidi".to_string()),
                            input_type: Some(".edgepkg.EdgeMessage".to_string()),
                            output_type: Some(".edgepkg.EdgeMessage".to_string()),
                            client_streaming: Some(true),
                            server_streaming: Some(true),
                            ..Default::default()
                        },
                    ],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        };
        fds.encode_to_vec()
    }

    fn protoc_available() -> bool {
        std::process::Command::new("protoc")
            .arg("--version")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    fn write_file(path: &Path, contents: &str) {
        std::fs::write(path, contents).unwrap();
    }

    fn test_message_descriptor() -> MessageDescriptor {
        Schema::from_descriptor_set(&test_descriptor_set())
            .unwrap()
            .find_message("testpkg.TestMessage")
            .unwrap()
    }

    fn snake_case_descriptor() -> MessageDescriptor {
        let fds = FileDescriptorSet {
            file: vec![FileDescriptorProto {
                name: Some("snake.proto".to_string()),
                package: Some("snakepkg".to_string()),
                syntax: Some("proto3".to_string()),
                message_type: vec![DescriptorProto {
                    name: Some("SnakeMessage".to_string()),
                    field: vec![FieldDescriptorProto {
                        name: Some("snake_case_name".to_string()),
                        number: Some(1),
                        label: Some(Label::Optional as i32),
                        r#type: Some(Type::String as i32),
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        };
        Schema::from_descriptor_set(&fds.encode_to_vec())
            .unwrap()
            .find_message("snakepkg.SnakeMessage")
            .unwrap()
    }

    fn build_test_protobuf(id: i64, name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        if id != 0 {
            append_key(&mut out, 1, 0);
            append_varint(&mut out, id as u64);
        }
        if !name.is_empty() {
            append_key(&mut out, 2, 2);
            append_len_bytes(&mut out, name.as_bytes());
        }
        out
    }

    fn build_name_only_protobuf(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        append_key(&mut out, 2, 2);
        append_len_bytes(&mut out, name.as_bytes());
        out
    }

    fn append_key(out: &mut Vec<u8>, field: u64, wire: u8) {
        append_varint(out, (field << 3) | u64::from(wire));
    }

    fn append_len_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
        append_varint(out, bytes.len() as u64);
        out.extend_from_slice(bytes);
    }

    fn append_varint(out: &mut Vec<u8>, mut value: u64) {
        while value >= 0x80 {
            out.push((value as u8 & 0x7f) | 0x80);
            value >>= 7;
        }
        out.push(value as u8);
    }

    fn json_map(bytes: &[u8]) -> serde_json::Map<String, serde_json::Value> {
        serde_json::from_slice::<serde_json::Value>(bytes)
            .unwrap()
            .as_object()
            .unwrap()
            .clone()
    }

    fn assert_json_id(map: &serde_json::Map<String, serde_json::Value>, want: &str, context: &str) {
        match map.get("id") {
            Some(serde_json::Value::String(value)) => assert_eq!(value, want, "{context}"),
            Some(serde_json::Value::Number(value)) => {
                assert_eq!(value.to_string(), want, "{context}")
            }
            other => panic!("{context}: unexpected id value {other:?}"),
        }
    }

    #[test]
    fn load_descriptor_set_finds_services_and_methods() {
        let schema = Schema::from_descriptor_set(&stream_descriptor_set()).unwrap();

        assert_eq!(schema.services(), ["streampkg.StreamService"]);
        let method = schema
            .find_method("streampkg.StreamService/ClientStream")
            .unwrap();
        assert!(method.is_client_streaming());
        assert_eq!(method.input().full_name(), "streampkg.StreamRequest");
        assert_eq!(method.output().full_name(), "streampkg.StreamResponse");
    }

    #[test]
    fn stream_json_to_grpc_frames_converts_multiple_messages() {
        let schema = Schema::from_descriptor_set(&stream_descriptor_set()).unwrap();
        let method = schema
            .find_method("streampkg.StreamService/ClientStream")
            .unwrap();

        let framed =
            stream_json_to_grpc_frames(br#"{"value":"one"}{"value":"two"}"#, &method.input())
                .unwrap();
        let frames = framing::read_frames(&framed).unwrap();

        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].data, b"\x0a\x03one");
        assert_eq!(frames[1].data, b"\x0a\x03two");
    }

    #[tokio::test]
    async fn json_reader_to_grpc_frame_stream_errors_on_oversized_unterminated_message() {
        let schema = Schema::from_descriptor_set(&stream_descriptor_set()).unwrap();
        let method = schema
            .find_method("streampkg.StreamService/ClientStream")
            .unwrap();
        let reader = std::io::Cursor::new(vec![b'['; 64]);
        let stream = json_reader_to_grpc_frame_stream_with_limit(reader, method.input(), 32);
        futures_util::pin_mut!(stream);

        let err = stream.try_next().await.unwrap_err();

        assert_eq!(
            err.to_string(),
            "gRPC JSON message exceeds 32 bytes before a complete JSON value"
        );
    }

    #[tokio::test]
    async fn json_reader_to_grpc_frame_stream_discards_whitespace_only_input() {
        let schema = Schema::from_descriptor_set(&stream_descriptor_set()).unwrap();
        let method = schema
            .find_method("streampkg.StreamService/ClientStream")
            .unwrap();
        let reader = std::io::Cursor::new(vec![b' '; 64]);
        let stream = json_reader_to_grpc_frame_stream_with_limit(reader, method.input(), 8);
        futures_util::pin_mut!(stream);

        assert!(stream.try_next().await.unwrap().is_none());
    }

    #[test]
    fn unary_json_to_protobuf_ignores_unknown_fields_like_go() {
        let schema = Schema::from_descriptor_set(&stream_descriptor_set()).unwrap();
        let method = schema
            .find_method("streampkg.StreamService/ClientStream")
            .unwrap();

        let encoded =
            json_to_protobuf(br#"{"value":"one","unknown":true}"#, &method.input()).unwrap();

        assert_eq!(encoded, b"\x0a\x03one");
    }

    #[test]
    fn describe_symbol_renders_service_method_and_message_like_go() {
        let schema = Schema::from_descriptor_set(&stream_descriptor_set()).unwrap();

        let service = describe_symbol(&schema, "streampkg.StreamService").unwrap();
        assert!(service.contains("service streampkg.StreamService"));
        assert!(service.contains("rpc: client-stream"));
        assert!(service.contains("request: streampkg.StreamRequest"));

        let method = describe_symbol(&schema, "streampkg.StreamService/ClientStream").unwrap();
        assert!(method.contains("method streampkg.StreamService/ClientStream"));
        assert!(method.contains("response: streampkg.StreamResponse"));

        let message = describe_symbol(&schema, "streampkg.StreamRequest").unwrap();
        assert!(message.contains("message streampkg.StreamRequest"));
        assert!(message.contains("1  value  optional  string"));
    }

    #[test]
    fn describe_symbol_normalizes_leading_dot_for_services_and_methods() {
        let schema = Schema::from_descriptor_set(&stream_descriptor_set()).unwrap();

        let service = describe_symbol(&schema, ".streampkg.StreamService").unwrap();
        assert!(service.contains("service streampkg.StreamService"));

        let dotted_method =
            describe_symbol(&schema, ".streampkg.StreamService.ClientStream").unwrap();
        assert!(dotted_method.contains("method streampkg.StreamService/ClientStream"));

        let slash_method =
            describe_symbol(&schema, ".streampkg.StreamService/ClientStream").unwrap();
        assert!(slash_method.contains("method streampkg.StreamService/ClientStream"));
    }

    #[test]
    fn test_load_descriptor_set_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.pb");
        std::fs::write(&path, test_descriptor_set()).unwrap();

        let schema = Schema::load_descriptor_set_file(path.to_str().unwrap()).unwrap();

        assert!(schema.find_message("testpkg.TestMessage").is_some());
    }

    #[test]
    fn test_load_descriptor_set_file_not_found() {
        let err = Schema::load_descriptor_set_file("/nonexistent/path/to/file.pb").unwrap_err();

        assert!(
            err.to_string()
                .contains("failed to read descriptor set file")
        );
    }

    #[test]
    fn test_load_descriptor_set_file_invalid_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("invalid.pb");
        std::fs::write(&path, b"not a valid protobuf").unwrap();

        let err = Schema::load_descriptor_set_file(path.to_str().unwrap()).unwrap_err();

        assert!(
            err.to_string()
                .contains("failed to create file descriptors")
        );
    }

    #[test]
    fn test_load_descriptor_set_bytes() {
        let schema = Schema::from_descriptor_set(&test_descriptor_set()).unwrap();

        assert!(schema.find_message("testpkg.TestMessage").is_some());
    }

    #[test]
    fn test_load_descriptor_set_bytes_empty() {
        let empty = FileDescriptorSet { file: vec![] }.encode_to_vec();
        let schema = Schema::from_descriptor_set(&empty).unwrap();

        assert!(schema.messages().is_empty());
        assert!(schema.services().is_empty());
    }

    #[test]
    fn test_load_descriptor_set_bytes_invalid() {
        let err = Schema::from_descriptor_set(b"not valid protobuf").unwrap_err();

        assert!(
            err.to_string()
                .contains("failed to create file descriptors")
        );
    }

    #[test]
    fn test_new_schema_equivalent_empty_descriptor_pool() {
        let empty = FileDescriptorSet { file: vec![] }.encode_to_vec();
        let schema = Schema::from_descriptor_set(&empty).unwrap();

        assert!(schema.messages().is_empty());
        assert!(schema.services().is_empty());
    }

    #[test]
    fn test_load_from_descriptor_set() {
        let schema = Schema::from_descriptor_set(&test_descriptor_set()).unwrap();

        assert!(schema.messages().len() >= 2);
        assert_eq!(schema.services(), ["testpkg.TestService"]);
    }

    #[test]
    fn test_find_message() {
        let schema = Schema::from_descriptor_set(&test_descriptor_set()).unwrap();
        let cases = [
            ("testpkg.TestMessage", true),
            (".testpkg.TestMessage", true),
            ("testpkg.NestedOuter.NestedInner", true),
            ("testpkg.NonExistent", false),
            ("wrongpkg.TestMessage", false),
        ];

        for (name, found) in cases {
            assert_eq!(
                schema.find_message(name).is_some(),
                found,
                "message lookup {name}"
            );
        }
    }

    #[test]
    fn test_find_service() {
        let schema = Schema::from_descriptor_set(&test_descriptor_set()).unwrap();
        let cases = [
            ("testpkg.TestService", true),
            (".testpkg.TestService", true),
            ("testpkg.NonExistent", false),
        ];

        for (name, found) in cases {
            assert_eq!(
                schema.find_service(name).is_some(),
                found,
                "service lookup {name}"
            );
        }
    }

    #[test]
    fn test_find_method() {
        let schema = Schema::from_descriptor_set(&test_descriptor_set()).unwrap();
        let cases = [
            ("testpkg.TestService/GetTest", true),
            ("testpkg.TestService.GetTest", true),
            ("testpkg.TestService/CreateTest", true),
            ("testpkg.NonExistent/GetTest", false),
            ("testpkg.TestService/NonExistent", false),
            ("InvalidMethodName", false),
        ];

        for (name, found) in cases {
            assert_eq!(
                schema.find_method(name).is_ok(),
                found,
                "method lookup {name}"
            );
        }
    }

    #[test]
    fn test_list_messages() {
        let schema = Schema::from_descriptor_set(&test_descriptor_set()).unwrap();
        let messages = schema.messages();

        assert!(messages.len() >= 3, "messages: {messages:?}");
        assert!(messages.contains(&"testpkg.TestMessage".to_string()));
        assert!(messages.contains(&"testpkg.NestedOuter".to_string()));
        assert!(messages.contains(&"testpkg.NestedOuter.NestedInner".to_string()));
    }

    #[test]
    fn test_list_services() {
        let schema = Schema::from_descriptor_set(&test_descriptor_set()).unwrap();

        assert_eq!(schema.services(), ["testpkg.TestService"]);
    }

    #[test]
    fn test_load_from_descriptor_set_error() {
        let empty = FileDescriptorSet { file: vec![] }.encode_to_vec();
        let schema = Schema::from_descriptor_set(&empty).unwrap();

        assert!(schema.messages().is_empty());
        assert!(schema.services().is_empty());
    }

    #[test]
    fn test_json_to_protobuf() {
        let desc = test_message_descriptor();

        assert!(
            !json_to_protobuf(br#"{"id": 123, "name": "test"}"#, &desc)
                .unwrap()
                .is_empty()
        );
        assert!(json_to_protobuf(br#"{}"#, &desc).unwrap().is_empty());
        assert!(
            !json_to_protobuf(br#"{"id": 456}"#, &desc)
                .unwrap()
                .is_empty()
        );
        assert!(
            !json_to_protobuf(br#"{"name": "only name"}"#, &desc)
                .unwrap()
                .is_empty()
        );
        assert!(json_to_protobuf(br#"{"id": 1, "unknownField": "ignored"}"#, &desc).is_ok());
        assert!(json_to_protobuf(br#"{invalid"#, &desc).is_err());
        assert!(json_to_protobuf(br#"{"id": "not a number"}"#, &desc).is_err());
    }

    #[test]
    fn test_protobuf_to_json() {
        let desc = test_message_descriptor();
        let cases = [
            (
                "simple message",
                build_test_protobuf(123, "test"),
                "123",
                "test",
            ),
            ("empty message", Vec::new(), "", ""),
            ("id only", build_test_protobuf(999, ""), "999", ""),
            ("name only", build_name_only_protobuf("hello"), "", "hello"),
        ];

        for (name, proto_input, want_id, want_name) in cases {
            let json = protobuf_to_json(&proto_input, &desc).unwrap();
            let result = json_map(&json);
            if !want_id.is_empty() {
                assert_json_id(&result, want_id, name);
            }
            if !want_name.is_empty() {
                assert_eq!(
                    result.get("name").and_then(|value| value.as_str()),
                    Some(want_name)
                );
            }
        }
    }

    #[test]
    fn test_protobuf_to_json_compact() {
        let desc = test_message_descriptor();
        let json = protobuf_to_json_compact(&build_test_protobuf(123, "test"), &desc).unwrap();

        assert!(!json.contains(&b'\n'));
        let result = json_map(&json);
        assert_json_id(&result, "123", "compact");
        assert_eq!(
            result.get("name").and_then(|value| value.as_str()),
            Some("test")
        );
    }

    #[test]
    fn protobuf_to_json_uses_proto_field_names_like_go() {
        let desc = snake_case_descriptor();
        let mut proto = Vec::new();
        append_key(&mut proto, 1, 2);
        append_len_bytes(&mut proto, b"kept");

        let json = protobuf_to_json(&proto, &desc).unwrap();
        let result = json_map(&json);

        assert_eq!(
            result
                .get("snake_case_name")
                .and_then(|value| value.as_str()),
            Some("kept")
        );
        assert!(!result.contains_key("snakeCaseName"));
    }

    #[test]
    fn test_json_to_protobuf_round_trip() {
        let desc = test_message_descriptor();
        let cases = [
            (
                "full message",
                br#"{"id": 42, "name": "roundtrip"}"#.as_slice(),
                "42",
                "roundtrip",
            ),
            (
                "zero values",
                br#"{"id": 0, "name": ""}"#.as_slice(),
                "",
                "",
            ),
            (
                "large id",
                br#"{"id": 9223372036854775807, "name": "max int64"}"#.as_slice(),
                "9223372036854775807",
                "max int64",
            ),
        ];

        for (name, json_input, want_id, want_name) in cases {
            let proto_data = json_to_protobuf(json_input, &desc).unwrap();
            let json = protobuf_to_json(&proto_data, &desc).unwrap();
            let result = json_map(&json);
            if !want_id.is_empty() {
                assert_json_id(&result, want_id, name);
            }
            if !want_name.is_empty() {
                assert_eq!(
                    result.get("name").and_then(|value| value.as_str()),
                    Some(want_name)
                );
            }
        }
    }

    #[test]
    fn test_json_to_protobuf_with_nested_message() {
        let schema = Schema::from_descriptor_set(&nested_descriptor_set()).unwrap();
        let desc = schema.find_message("nested.Outer").unwrap();

        let proto_data = json_to_protobuf(
            br#"{"inner": {"value": "nested value"}, "count": 5}"#,
            &desc,
        )
        .unwrap();
        let json = protobuf_to_json(&proto_data, &desc).unwrap();
        let result = json_map(&json);

        let inner = result
            .get("inner")
            .and_then(|value| value.as_object())
            .unwrap();
        assert_eq!(
            inner.get("value").and_then(|value| value.as_str()),
            Some("nested value")
        );
        assert_eq!(
            result.get("count").and_then(|value| value.as_i64()),
            Some(5)
        );
    }

    #[test]
    fn json_to_protobuf_handles_repeated_maps_oneofs_bytes_and_enums() {
        let schema = Schema::from_descriptor_set(&edge_descriptor_set()).unwrap();
        let desc = schema.find_message("edgepkg.EdgeMessage").unwrap();

        let proto_data = json_to_protobuf(
            br#"{
                "flag": true,
                "blob": "aGVsbG8=",
                "state": "STATE_READY",
                "scores": [-1, 0, 7],
                "labels": {"low": 1, "high": 9},
                "choice_text": "selected",
                "maybe": "present"
            }"#,
            &desc,
        )
        .unwrap();
        let json = protobuf_to_json(&proto_data, &desc).unwrap();
        let result = serde_json::from_slice::<serde_json::Value>(&json).unwrap();

        assert_eq!(result["flag"], true);
        assert_eq!(result["blob"], "aGVsbG8=");
        assert_eq!(result["state"], "STATE_READY");
        assert_eq!(result["scores"], serde_json::json!([-1, 0, 7]));
        assert_eq!(result["labels"]["low"], 1);
        assert_eq!(result["labels"]["high"], 9);
        assert_eq!(result["choice_text"], "selected");
        assert_eq!(result["maybe"], "present");
        assert!(result.get("choiceText").is_none());
    }

    #[test]
    fn json_to_protobuf_rejects_invalid_edge_shapes() {
        let schema = Schema::from_descriptor_set(&edge_descriptor_set()).unwrap();
        let desc = schema.find_message("edgepkg.EdgeMessage").unwrap();

        let cases: &[(&str, &[u8])] = &[
            ("invalid base64 bytes", br#"{"blob":"not base64!"}"#),
            ("wrong repeated shape", br#"{"scores": 1}"#),
            ("wrong map shape", br#"{"labels": [{"key":"a","value":1}]}"#),
            (
                "oneof conflict",
                br#"{"choice_text":"text","choice_count":"2"}"#,
            ),
            ("trailing JSON", br#"{"flag":true} garbage"#),
        ];

        for (name, json) in cases {
            assert!(json_to_protobuf(json, &desc).is_err(), "{name}");
        }
    }

    #[test]
    fn describe_symbol_reports_streaming_method_shapes() {
        let schema = Schema::from_descriptor_set(&edge_descriptor_set()).unwrap();

        let server_stream = describe_symbol(&schema, "edgepkg.EdgeService/ServerStream").unwrap();
        assert!(server_stream.contains("rpc: server-stream"));

        let bidi = describe_symbol(&schema, "edgepkg.EdgeService/Bidi").unwrap();
        assert!(bidi.contains("rpc: bidi-stream"));
    }

    #[test]
    fn test_compile_protos_success() {
        if !protoc_available() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let proto_file = dir.path().join("test.proto");
        write_file(
            &proto_file,
            r#"
syntax = "proto3";
package testcompile;

message TestRequest {
  int64 id = 1;
  string name = 2;
}

message TestResponse {
  bool success = 1;
  string message = 2;
}

service TestService {
  rpc GetTest(TestRequest) returns (TestResponse);
}
"#,
        );

        let schema = compile_protos(&[proto_file.display().to_string()], &[]).unwrap();

        assert!(schema.find_message("testcompile.TestRequest").is_some());
        assert!(schema.find_message("testcompile.TestResponse").is_some());
        assert!(schema.find_service("testcompile.TestService").is_some());
        assert!(
            schema
                .find_method("testcompile.TestService/GetTest")
                .is_ok()
        );
    }

    #[test]
    fn test_compile_protos_with_imports() {
        if !protoc_available() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let common_dir = dir.path().join("common");
        let service_dir = dir.path().join("service");
        std::fs::create_dir_all(&common_dir).unwrap();
        std::fs::create_dir_all(&service_dir).unwrap();
        let common_proto = common_dir.join("common.proto");
        let service_proto = service_dir.join("service.proto");
        write_file(
            &common_proto,
            r#"
syntax = "proto3";
package common;

message Timestamp {
  int64 seconds = 1;
  int32 nanos = 2;
}
"#,
        );
        write_file(
            &service_proto,
            r#"
syntax = "proto3";
package myservice;

import "common/common.proto";

message Event {
  string id = 1;
  common.Timestamp timestamp = 2;
}
"#,
        );

        let schema = compile_protos(
            &[service_proto.display().to_string()],
            &[dir.path().display().to_string()],
        )
        .unwrap();

        assert!(schema.find_message("myservice.Event").is_some());
        assert!(schema.find_message("common.Timestamp").is_some());
    }

    #[test]
    fn test_compile_protos_file_not_found() {
        if !protoc_available() {
            return;
        }

        let err =
            compile_protos(&["/nonexistent/path/to/file.proto".to_string()], &[]).unwrap_err();

        assert!(matches!(err, ProtoError::Protoc(_)));
        assert!(err.to_string().starts_with("protoc failed: "));
    }

    #[test]
    fn test_compile_protos_invalid_syntax() {
        if !protoc_available() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let proto_file = dir.path().join("invalid.proto");
        write_file(
            &proto_file,
            r#"
this is not valid proto syntax!!!
message {
  broken = 1;
}
"#,
        );

        let err = compile_protos(&[proto_file.display().to_string()], &[]).unwrap_err();

        match err {
            ProtoError::Protoc(message) => assert!(!message.is_empty()),
            other => panic!("expected Protoc error, got {other:?}"),
        }
    }

    #[test]
    fn test_compile_protos_multiple_files() {
        if !protoc_available() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("first.proto");
        let second = dir.path().join("second.proto");
        write_file(
            &first,
            r#"
syntax = "proto3";
package first;

message FirstMessage {
  string value = 1;
}
"#,
        );
        write_file(
            &second,
            r#"
syntax = "proto3";
package second;

message SecondMessage {
  int32 count = 1;
}
"#,
        );

        let schema = compile_protos(
            &[first.display().to_string(), second.display().to_string()],
            &[],
        )
        .unwrap();

        assert!(schema.find_message("first.FirstMessage").is_some());
        assert!(schema.find_message("second.SecondMessage").is_some());
    }

    #[test]
    fn test_protoc_not_found_error() {
        let message = ProtoError::ProtocNotFound.to_string();
        assert!(message.contains("protoc not found in PATH"));
        assert!(message.len() >= 10);
    }

    #[test]
    fn test_protoc_error() {
        let message = ProtoError::Protoc("test error message".to_string()).to_string();
        assert_eq!(message, "protoc failed: test error message");
    }
}
