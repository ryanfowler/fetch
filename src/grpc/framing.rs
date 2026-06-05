use std::fmt;

pub const MAX_MESSAGE_SIZE: usize = 64 * 1024 * 1024;
const FRAME_HEADER_LEN: usize = 5;

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

pub fn frame(data: &[u8], compressed: bool) -> Result<Vec<u8>, FrameError> {
    validate_length(data.len())?;
    let length = u32::try_from(data.len())
        .map_err(|_| FrameError(format!("gRPC message too large: {} bytes", data.len())))?;
    let mut out = Vec::with_capacity(5 + data.len());
    out.push(u8::from(compressed));
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(data);
    Ok(out)
}

pub fn unframe(data: &[u8]) -> Result<Frame, FrameError> {
    if data.len() < FRAME_HEADER_LEN {
        return Err(FrameError(
            "failed to read gRPC frame header: insufficient data".to_string(),
        ));
    }

    let compressed = compressed_flag(data[0])?;
    let length = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
    validate_length(length as usize)?;

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

pub fn read_frames(data: &[u8]) -> Result<Vec<Frame>, FrameError> {
    let mut decoder = FrameDecoder::new();
    let frames = decoder.push(data)?;
    decoder.finish()?;
    Ok(frames)
}

#[derive(Debug, Default)]
pub struct FrameDecoder {
    header: [u8; FRAME_HEADER_LEN],
    header_len: usize,
    current: Option<PartialFrame>,
}

#[derive(Debug)]
struct PartialFrame {
    data: Vec<u8>,
    len: usize,
    compressed: bool,
}

impl FrameDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, mut chunk: &[u8]) -> Result<Vec<Frame>, FrameError> {
        let mut frames = Vec::new();
        while !chunk.is_empty() {
            if let Some(partial) = self.current.as_mut() {
                let remaining = partial.len - partial.data.len();
                let take = remaining.min(chunk.len());
                partial.data.extend_from_slice(&chunk[..take]);
                chunk = &chunk[take..];

                if partial.data.len() == partial.len {
                    let partial = self.current.take().expect("partial frame exists");
                    frames.push(Frame {
                        data: partial.data,
                        compressed: partial.compressed,
                    });
                }
                continue;
            }

            let take = (FRAME_HEADER_LEN - self.header_len).min(chunk.len());
            self.header[self.header_len..self.header_len + take].copy_from_slice(&chunk[..take]);
            self.header_len += take;
            chunk = &chunk[take..];

            if self.header_len == FRAME_HEADER_LEN {
                let compressed = compressed_flag(self.header[0])?;
                let length = u32::from_be_bytes([
                    self.header[1],
                    self.header[2],
                    self.header[3],
                    self.header[4],
                ]) as usize;
                validate_length(length)?;
                self.header_len = 0;

                if length == 0 {
                    frames.push(Frame {
                        data: Vec::new(),
                        compressed,
                    });
                } else {
                    self.current = Some(PartialFrame {
                        data: Vec::with_capacity(length),
                        len: length,
                        compressed,
                    });
                }
            }
        }
        Ok(frames)
    }

    pub fn finish(&self) -> Result<(), FrameError> {
        if self.header_len > 0 {
            return Err(FrameError(
                "failed to read gRPC frame header: incomplete header".to_string(),
            ));
        }
        if self.current.is_some() {
            return Err(FrameError(
                "failed to read gRPC message: incomplete data".to_string(),
            ));
        }
        Ok(())
    }
}

fn validate_length(length: usize) -> Result<(), FrameError> {
    if length > MAX_MESSAGE_SIZE {
        return Err(FrameError(format!(
            "gRPC message too large: {length} bytes"
        )));
    }
    Ok(())
}

fn compressed_flag(byte: u8) -> Result<bool, FrameError> {
    match byte {
        0 => Ok(false),
        1 => Ok(true),
        flag => Err(FrameError(format!(
            "invalid gRPC compressed flag {flag}; expected 0 or 1"
        ))),
    }
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
            assert_eq!(frame(&data, compressed).unwrap(), want, "{name}");
        }

        let large = vec![0xab; 256];
        let mut want = vec![0x00, 0x00, 0x00, 0x01, 0x00];
        want.extend_from_slice(&large);
        assert_eq!(frame(&large, false).unwrap(), want, "larger message");
    }

    #[test]
    fn test_frame_large_message_rejected() {
        let large = vec![0xab; MAX_MESSAGE_SIZE + 1];
        let err = frame(&large, false).unwrap_err();
        assert!(err.to_string().contains("gRPC message too large"));
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
            let framed = frame(&data, false).unwrap();
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
    fn test_unframe_invalid_compressed_flag_rejected() {
        for flag in [2, 255] {
            let input = [flag, 0x00, 0x00, 0x00, 0x00];
            let err = unframe(&input).unwrap_err();
            assert_eq!(
                err.to_string(),
                format!("invalid gRPC compressed flag {flag}; expected 0 or 1")
            );
        }
    }

    #[test]
    fn test_read_frames() {
        let one = frame(&[0x01, 0x02, 0x03], false).unwrap();
        let two = frame(&[0x04], true).unwrap();
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

    #[test]
    fn test_frame_decoder_rejects_large_message_after_header() {
        let mut decoder = FrameDecoder::new();
        let header = [0x00, 0x04, 0x00, 0x00, 0x01];
        let err = decoder.push(&header).unwrap_err();
        assert!(err.to_string().contains("gRPC message too large"));
    }

    #[test]
    fn test_frame_decoder_rejects_invalid_compressed_flag() {
        for flag in [2, 255] {
            let mut decoder = FrameDecoder::new();
            let header = [flag, 0x00, 0x00, 0x00, 0x00];
            assert!(decoder.push(&header[..2]).unwrap().is_empty());
            let err = decoder.push(&header[2..]).unwrap_err();
            assert_eq!(
                err.to_string(),
                format!("invalid gRPC compressed flag {flag}; expected 0 or 1")
            );
        }
    }

    #[test]
    fn test_frame_decoder_accepts_split_frames() {
        let framed = frame(&[0x01, 0x02, 0x03], false).unwrap();
        let mut decoder = FrameDecoder::new();
        assert!(decoder.push(&framed[..2]).unwrap().is_empty());
        assert!(decoder.push(&framed[2..6]).unwrap().is_empty());
        let frames = decoder.push(&framed[6..]).unwrap();
        decoder.finish().unwrap();

        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].data, vec![0x01, 0x02, 0x03]);
        assert!(!frames[0].compressed);
    }
}
