mod decode;
mod external;
mod orientation;
mod render;
mod terminal;

pub use decode::DecodeMode;

use decode::decode_image;
use orientation::orient_image;
use render::{write_blocks, write_inline, write_kitty};
use terminal::{Protocol, RenderOptions, detect_protocol, supports_true_color, terminal_size};

#[derive(Debug, thiserror::Error)]
pub enum ImageError {
    #[error("{0}")]
    Message(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Decode(#[from] ::image::ImageError),
}

pub fn render(bytes: &[u8], decode_mode: DecodeMode) -> Result<Vec<u8>, ImageError> {
    let size = terminal_size()?;
    let protocol = if size.width_px == 0 || size.height_px == 0 {
        Protocol::Block
    } else {
        detect_protocol()
    };
    let options = RenderOptions {
        size,
        protocol,
        true_color: supports_true_color(),
    };
    render_with_options(bytes, decode_mode, options)
}

fn render_with_options(
    bytes: &[u8],
    decode_mode: DecodeMode,
    options: RenderOptions,
) -> Result<Vec<u8>, ImageError> {
    let img = oriented_decoded_image(bytes, decode_image(bytes, decode_mode)?);
    if img.width() == 0 || img.height() == 0 {
        return Ok(Vec::new());
    }
    match options.protocol {
        Protocol::Block => Ok(write_blocks(
            &img,
            options.size.cols,
            options.size.rows,
            options.true_color,
        )),
        Protocol::Inline => write_inline(&img, options.size.width_px, options.size.height_px),
        Protocol::Kitty => write_kitty(&img, options.size.width_px, options.size.height_px),
    }
}

fn oriented_decoded_image(bytes: &[u8], decoded: decode::DecodedImage) -> ::image::DynamicImage {
    if decoded.orientation_applied() {
        decoded.into_image()
    } else {
        orient_image(bytes, decoded.into_image())
    }
}

#[cfg(test)]
mod tests {
    use super::decode::DecodedImage;
    use super::terminal::{Protocol, RenderOptions, TerminalSize};
    use super::{DecodeMode, oriented_decoded_image, render_with_options};
    use ::image::codecs::png::PngEncoder;
    use ::image::{ColorType, DynamicImage, ImageEncoder, Rgba, RgbaImage};

    fn img_1x2() -> DynamicImage {
        let mut img = RgbaImage::new(1, 2);
        img.put_pixel(0, 0, Rgba([255, 0, 0, 255]));
        img.put_pixel(0, 1, Rgba([0, 0, 255, 255]));
        DynamicImage::ImageRgba8(img)
    }

    fn png_bytes(img: &DynamicImage) -> Vec<u8> {
        let rgba = img.to_rgba8();
        let mut out = Vec::new();
        PngEncoder::new(&mut out)
            .write_image(
                rgba.as_raw(),
                rgba.width(),
                rgba.height(),
                ColorType::Rgba8.into(),
            )
            .unwrap();
        out
    }

    #[test]
    fn render_with_options_decodes_png_and_renders_blocks() {
        let bytes = png_bytes(&img_1x2());
        let out = render_with_options(
            &bytes,
            DecodeMode::BuiltIn,
            RenderOptions {
                size: TerminalSize {
                    cols: 1,
                    rows: 1,
                    width_px: 0,
                    height_px: 0,
                },
                protocol: Protocol::Block,
                true_color: true,
            },
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "\x1b[48;2;255;0;0m\x1b[38;2;0;0;255m▄\x1b[0m\n"
        );
    }

    #[test]
    fn built_in_decode_applies_input_orientation_once() {
        let img = DynamicImage::ImageRgba8({
            let mut img = RgbaImage::new(2, 1);
            img.put_pixel(0, 0, Rgba([1, 0, 0, 255]));
            img.put_pixel(1, 0, Rgba([2, 0, 0, 255]));
            img
        });

        let oriented = oriented_decoded_image(
            &jpeg_with_orientation(6),
            DecodedImage::needs_orientation(img),
        )
        .to_rgba8();

        assert_eq!(oriented.dimensions(), (1, 2));
        assert_eq!(oriented.get_pixel(0, 0)[0], 1);
        assert_eq!(oriented.get_pixel(0, 1)[0], 2);
    }

    #[test]
    fn external_decode_does_not_apply_input_orientation_twice() {
        let already_oriented = DynamicImage::ImageRgba8({
            let mut img = RgbaImage::new(1, 2);
            img.put_pixel(0, 0, Rgba([1, 0, 0, 255]));
            img.put_pixel(0, 1, Rgba([2, 0, 0, 255]));
            img
        });

        let got = oriented_decoded_image(
            &jpeg_with_orientation(6),
            DecodedImage::already_oriented(already_oriented),
        )
        .to_rgba8();

        assert_eq!(got.dimensions(), (1, 2));
        assert_eq!(got.get_pixel(0, 0)[0], 1);
        assert_eq!(got.get_pixel(0, 1)[0], 2);
    }

    fn jpeg_with_orientation(orientation: u16) -> Vec<u8> {
        let mut app1 = Vec::new();
        app1.extend_from_slice(b"Exif\0\0");
        app1.extend_from_slice(&0x4d4d_u16.to_be_bytes());
        app1.extend_from_slice(&42_u16.to_be_bytes());
        app1.extend_from_slice(&8_u32.to_be_bytes());
        app1.extend_from_slice(&1_u16.to_be_bytes());
        app1.extend_from_slice(&0x0112_u16.to_be_bytes());
        app1.extend_from_slice(&3_u16.to_be_bytes());
        app1.extend_from_slice(&1_u32.to_be_bytes());
        app1.extend_from_slice(&orientation.to_be_bytes());
        app1.extend_from_slice(&0_u16.to_be_bytes());

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0xffd8_u16.to_be_bytes());
        bytes.extend_from_slice(&0xffe1_u16.to_be_bytes());
        bytes.extend_from_slice(&u16::try_from(app1.len() + 2).unwrap().to_be_bytes());
        bytes.extend_from_slice(&app1);
        bytes
    }
}
