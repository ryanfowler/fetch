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
    let img = orient_image(bytes, decode_image(bytes, decode_mode)?);
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

#[cfg(test)]
mod tests {
    use super::terminal::{Protocol, RenderOptions, TerminalSize};
    use super::{DecodeMode, render_with_options};
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
            "\x1b[48;2;255;0;0m\x1b[38;2;0;0;255m▄\x1b[0m\n\x1b[0m"
        );
    }
}
