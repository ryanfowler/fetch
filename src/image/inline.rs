use std::io::{self, Seek, Write};

use base64::{engine::general_purpose::STANDARD, Engine};
use image::{codecs::jpeg::JpegEncoder, DynamicImage, GenericImageView, ImageFormat};

use super::Image;

pub(crate) fn write_to_stdout(img: Image) -> io::Result<()> {
    let img = img.resize_for_term();
    let img = img.dynamic_image();

    let mut buf = Vec::with_capacity(img.as_bytes().len());
    let mut cursor = io::Cursor::new(&mut buf);
    encode_image(&mut cursor, img)?;

    let (width, height) = img.dimensions();
    let mut stdout = io::stdout();
    writeln!(
        &mut stdout,
        "\x1b]1337;File=inline=1;preserveAspectRatio=1;size={};width={}px;height={}px:{}\x07",
        buf.len(),
        width,
        height,
        STANDARD.encode(&buf)
    )?;
    stdout.flush()
}

fn encode_image<W: Write + Seek>(w: &mut W, img: &DynamicImage) -> io::Result<()> {
    let (width, height) = img.dimensions();
    if img.color().has_alpha() {
        image::write_buffer_with_format(
            w,
            &img.to_rgba8(),
            width,
            height,
            img.color(),
            ImageFormat::Png,
        )
    } else {
        JpegEncoder::new_with_quality(w, 75).encode_image(img)
    }
    .map_err(io::Error::other)
}
