use std::io::{self, Seek, Write};

use base64::{engine::general_purpose::STANDARD, Engine};
use image::{codecs::jpeg::JpegEncoder, DynamicImage, GenericImageView, ImageFormat};

pub(crate) fn write_to_stdout(img: &DynamicImage) -> io::Result<()> {
    let mut buf = Vec::with_capacity(img.as_bytes().len());
    let mut cursor = io::Cursor::new(&mut buf);
    encode_image(&mut cursor, img)?;

    let (cols, rows) = super::get_out_dims(img)?;
    let mut stdout = io::stdout();
    writeln!(
        &mut stdout,
        "\x1b]1337;File=inline=1;preserveAspectRatio=1;size={};width={};height={}:{}\x07",
        buf.len(),
        cols,
        rows,
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
