use std::io::Cursor;

use ::image::{DynamicImage, GenericImageView};

use super::ImageError;
use super::external::decode_with_adaptors;

const IMAGE_DIMENSION_LIMIT: u32 = 8192;
const IMAGE_DECODE_MAX_ALLOC_BYTES: u64 =
    IMAGE_DIMENSION_LIMIT as u64 * IMAGE_DIMENSION_LIMIT as u64 * 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeMode {
    BuiltIn,
    External,
}

#[derive(Debug)]
pub(crate) struct DecodedImage {
    image: DynamicImage,
    orientation_applied: bool,
}

impl DecodedImage {
    pub(crate) fn needs_orientation(image: DynamicImage) -> Self {
        Self {
            image,
            orientation_applied: false,
        }
    }

    pub(crate) fn already_oriented(image: DynamicImage) -> Self {
        Self {
            image,
            orientation_applied: true,
        }
    }

    pub(crate) fn orientation_applied(&self) -> bool {
        self.orientation_applied
    }

    pub(crate) fn into_image(self) -> DynamicImage {
        self.image
    }
}

pub(crate) fn decode_image(
    bytes: &[u8],
    decode_mode: DecodeMode,
) -> Result<DecodedImage, ImageError> {
    match decode_image_std(bytes) {
        Ok(img) => Ok(DecodedImage::needs_orientation(img)),
        Err(err) if decode_mode == DecodeMode::BuiltIn => Err(err),
        Err(err) => match decode_with_adaptors(bytes) {
            Ok(img) => Ok(img),
            Err(_) => Err(err),
        },
    }
}

pub(crate) fn decode_image_std(bytes: &[u8]) -> Result<DynamicImage, ImageError> {
    let mut reader = ::image::ImageReader::new(Cursor::new(bytes)).with_guessed_format()?;
    reader.limits(image_decode_limits());
    let img = reader.decode()?;
    let (width, height) = img.dimensions();
    if width > IMAGE_DIMENSION_LIMIT || height > IMAGE_DIMENSION_LIMIT {
        return Err(ImageError::Message(format!(
            "image dimensions are too large {width}x{height}"
        )));
    }
    Ok(img)
}

fn image_decode_limits() -> ::image::Limits {
    let mut limits = ::image::Limits::default();
    limits.max_image_width = Some(IMAGE_DIMENSION_LIMIT);
    limits.max_image_height = Some(IMAGE_DIMENSION_LIMIT);
    limits.max_alloc = Some(IMAGE_DECODE_MAX_ALLOC_BYTES);
    limits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_rejects_oversized_png_dimensions_before_full_allocation() {
        let bytes = png_with_dimensions(IMAGE_DIMENSION_LIMIT + 1, IMAGE_DIMENSION_LIMIT + 1);
        let err = decode_image_std(&bytes).unwrap_err();

        assert!(matches!(
            err,
            ImageError::Decode(::image::ImageError::Limits(_))
        ));
    }

    #[test]
    fn builtin_decode_mode_rejects_unsupported_bytes_without_external_adaptors() {
        let err = decode_image(b"not an image", DecodeMode::BuiltIn).unwrap_err();
        assert!(matches!(err, ImageError::Decode(_)));
    }

    fn png_with_dimensions(width: u32, height: u32) -> Vec<u8> {
        let mut bytes = Vec::from(&[137, 80, 78, 71, 13, 10, 26, 10]);
        let mut ihdr = Vec::new();
        ihdr.extend_from_slice(&width.to_be_bytes());
        ihdr.extend_from_slice(&height.to_be_bytes());
        ihdr.extend_from_slice(&[8, 6, 0, 0, 0]);
        append_png_chunk(&mut bytes, b"IHDR", &ihdr);
        append_png_chunk(&mut bytes, b"IEND", &[]);
        bytes
    }

    fn append_png_chunk(bytes: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
        bytes.extend_from_slice(&u32::try_from(data.len()).unwrap().to_be_bytes());
        bytes.extend_from_slice(kind);
        bytes.extend_from_slice(data);
        bytes.extend_from_slice(&png_crc32(kind, data).to_be_bytes());
    }

    fn png_crc32(kind: &[u8; 4], data: &[u8]) -> u32 {
        let mut crc = 0xffff_ffff_u32;
        for byte in kind.iter().chain(data) {
            crc ^= u32::from(*byte);
            for _ in 0..8 {
                crc = if crc & 1 == 0 {
                    crc >> 1
                } else {
                    (crc >> 1) ^ 0xedb8_8320
                };
            }
        }
        !crc
    }
}
