use std::{
    cmp::min,
    io::{self, Write},
};

use base64::{engine::general_purpose::STANDARD, Engine};
use flate2::{write::ZlibEncoder, Compression};
use image::DynamicImage;

use super::Image;

static ESC: &str = "\x1b";

pub(crate) fn write_to_stdout(img: Image) -> std::io::Result<()> {
    let img = img.resize_for_term();

    // Compress with zlib to improve remote sessions, then base64 encode.
    let (format, encoded) = encode_image(img.dynamic_image())?;

    let mut pos = 0;
    let mut stdout = io::BufWriter::with_capacity(1 << 18, io::stdout());

    {
        // Write the first chunk.
        let (width, height) = img.dimensions();
        let next = min(pos + 4096, encoded.len());
        let chunk = &encoded[pos..next];
        pos = next;
        write!(
            &mut stdout,
            "{ESC}_Gq=2,f={},a=T,t=d,s={},v={},o=z,m={};{}{ESC}\\",
            format,
            width,
            height,
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
        // Estimate a minimum 20% reduction in size.
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
