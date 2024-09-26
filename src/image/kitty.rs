use std::{
    cmp::min,
    io::{self, Write},
};

use base64::{engine::general_purpose::STANDARD, Engine};
use flate2::{write::ZlibEncoder, Compression};
use image::DynamicImage;

static ESC: &str = "\x1b";

pub(crate) fn write_to_stdout(img: &DynamicImage) -> std::io::Result<()> {
    // Compress with zlib to improve remote sessions, then base64 encode.
    let (format, encoded) = encode_image(img)?;

    let mut pos = 0;
    let mut stdout = io::BufWriter::with_capacity(1 << 18, io::stdout());

    {
        // Write the first chunk.
        let (cols, rows) = super::get_out_dims(img)?;
        let next = min(pos + 4096, encoded.len());
        let chunk = &encoded[pos..next];
        pos = next;
        write!(
            &mut stdout,
            "{ESC}_Gq=2,f={},a=T,t=d,s={},v={},c={},r={},o=z,m={};{}{ESC}\\",
            format,
            img.width(),
            img.height(),
            cols,
            rows,
            u8::from(pos < encoded.len()),
            chunk,
        )?;
    }

    // Write the remainder of the base64 zlib-compressed raw image.
    while pos < encoded.len() {
        let next = min(pos + 4096, encoded.len());
        let chunk = &encoded[pos..next];
        pos = next;
        write!(
            &mut stdout,
            "{ESC}_Gm={};{}{ESC}\\",
            u8::from(pos < encoded.len()),
            chunk
        )?;
    }
    writeln!(&mut stdout)?;
    stdout.flush()
}

fn encode_image(img: &DynamicImage) -> io::Result<(u8, String)> {
    let mut c = ZlibEncoder::new(
        Vec::with_capacity(img.as_bytes().len() * 4 / 5),
        Compression::fast(),
    );
    let format = match img {
        DynamicImage::ImageRgb8(img) => {
            c.write_all(img.as_raw())?;
            24
        }
        DynamicImage::ImageRgba8(img) => {
            c.write_all(img.as_raw())?;
            32
        }
        _ => {
            c.write_all(&img.to_rgb8())?;
            24
        }
    };
    let encoded = STANDARD.encode(&c.finish()?);
    Ok((format, encoded))
}
