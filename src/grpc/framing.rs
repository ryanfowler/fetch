use std::fmt;

const MAX_MESSAGE_SIZE: u32 = 64 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub data: Vec<u8>,
    pub compressed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameError(String);

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for FrameError {}

pub fn frame(data: &[u8], compressed: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + data.len());
    out.push(u8::from(compressed));
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
    out
}

pub fn unframe(data: &[u8]) -> Result<Frame, FrameError> {
    if data.len() < 5 {
        return Err(FrameError(
            "failed to read gRPC frame header: insufficient data".to_string(),
        ));
    }

    let compressed = data[0] != 0;
    let length = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
    validate_length(length)?;

    let end = 5 + length as usize;
    if data.len() < end {
        return Err(FrameError(
            "failed to read gRPC message: insufficient data".to_string(),
        ));
    }

    Ok(Frame {
        data: data[5..end].to_vec(),
        compressed,
    })
}

pub fn read_frames(mut data: &[u8]) -> Result<Vec<Frame>, FrameError> {
    let mut frames = Vec::new();
    while !data.is_empty() {
        if data.len() < 5 {
            return Err(FrameError(
                "failed to read gRPC frame header: incomplete header".to_string(),
            ));
        }

        let compressed = data[0] != 0;
        let length = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
        validate_length(length)?;

        let end = 5 + length as usize;
        if data.len() < end {
            return Err(FrameError(
                "failed to read gRPC message: incomplete data".to_string(),
            ));
        }

        frames.push(Frame {
            data: data[5..end].to_vec(),
            compressed,
        });
        data = &data[end..];
    }
    Ok(frames)
}

fn validate_length(length: u32) -> Result<(), FrameError> {
    if length > MAX_MESSAGE_SIZE {
        return Err(FrameError(format!(
            "gRPC message too large: {length} bytes"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame() {
        let cases = [
            (
                "empty uncompressed",
                Vec::new(),
                false,
                vec![0x00, 0x00, 0x00, 0x00, 0x00],
            ),
            (
                "simple uncompressed",
                vec![0x01, 0x02, 0x03],
                false,
                vec![0x00, 0x00, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03],
            ),
            (
                "simple compressed",
                vec![0x01, 0x02, 0x03],
                true,
                vec![0x01, 0x00, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03],
            ),
        ];

        for (name, data, compressed, want) in cases {
            assert_eq!(frame(&data, compressed), want, "{name}");
        }

        let large = vec![0xab; 256];
        let mut want = vec![0x00, 0x00, 0x00, 0x01, 0x00];
        want.extend_from_slice(&large);
        assert_eq!(frame(&large, false), want, "larger message");
    }

    #[test]
    fn test_unframe() {
        let cases = [
            (
                "empty message",
                vec![0x00, 0x00, 0x00, 0x00, 0x00],
                Some((Vec::new(), false)),
            ),
            (
                "simple uncompressed",
                vec![0x00, 0x00, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03],
                Some((vec![0x01, 0x02, 0x03], false)),
            ),
            (
                "simple compressed",
                vec![0x01, 0x00, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03],
                Some((vec![0x01, 0x02, 0x03], true)),
            ),
            ("truncated header", vec![0x00, 0x00, 0x00], None),
            (
                "truncated data",
                vec![0x00, 0x00, 0x00, 0x00, 0x05, 0x01, 0x02],
                None,
            ),
            ("empty input", Vec::new(), None),
        ];

        for (name, input, want) in cases {
            let got = unframe(&input);
            match want {
                Some((want_data, want_compressed)) => {
                    let got = got.unwrap_or_else(|err| panic!("{name}: {err}"));
                    assert_eq!(got.data, want_data, "{name}");
                    assert_eq!(got.compressed, want_compressed, "{name}");
                }
                None => assert!(got.is_err(), "{name}"),
            }
        }
    }

    #[test]
    fn test_frame_unframe_round_trip() {
        for data in [
            Vec::new(),
            vec![0x00],
            vec![0x01, 0x02, 0x03, 0x04, 0x05],
            vec![0xab; 1000],
        ] {
            let framed = frame(&data, false);
            let unframed = unframe(&framed).unwrap();
            assert!(!unframed.compressed);
            assert_eq!(unframed.data, data);
        }
    }

    #[test]
    fn test_unframe_large_message_rejected() {
        let header = [0x00, 0x10, 0x00, 0x00, 0x00];
        let err = unframe(&header).unwrap_err();
        assert!(err.to_string().contains("gRPC message too large"));
    }

    #[test]
    fn test_read_frames() {
        let one = frame(&[0x01, 0x02, 0x03], false);
        let two = frame(&[0x04], true);
        let mut stream = one.clone();
        stream.extend_from_slice(&two);

        let frames = read_frames(&stream).unwrap();
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].data, vec![0x01, 0x02, 0x03]);
        assert!(!frames[0].compressed);
        assert_eq!(frames[1].data, vec![0x04]);
        assert!(frames[1].compressed);

        assert!(read_frames(&[]).unwrap().is_empty());
        assert!(read_frames(&[0x00, 0x00]).is_err());
        assert!(read_frames(&[0x00, 0x00, 0x00, 0x00, 0x05, 0x01]).is_err());
    }
}
