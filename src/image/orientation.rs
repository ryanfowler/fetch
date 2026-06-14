use std::io::{Cursor, Read};

use ::image::{DynamicImage, RgbaImage};

pub(crate) fn orient_image(bytes: &[u8], img: DynamicImage) -> DynamicImage {
    match parse_orientation(Cursor::new(bytes)) {
        2 => mirror_horizontal(&img),
        3 => rotate180(&img),
        4 => mirror_vertical(&img),
        5 => rotate270(&mirror_horizontal(&img)),
        6 => rotate90(&img),
        7 => rotate90(&mirror_horizontal(&img)),
        8 => rotate270(&img),
        _ => img,
    }
}

fn parse_orientation<R: Read>(mut reader: R) -> u16 {
    if read_u16_be(&mut reader).unwrap_or_default() != 0xffd8 {
        return 0;
    }

    let mut scratch = [0_u8; 4096];
    loop {
        let marker = match read_u16_be(&mut reader) {
            Some(marker) => marker,
            None => return 0,
        };
        let length = match read_u16_be(&mut reader) {
            Some(length) if length >= 2 => length,
            _ => return 0,
        };
        if marker == 0xffe1 {
            let mut segment = reader.take(u64::from(length - 2));
            return parse_exif_segment(&mut segment, &mut scratch);
        }
        if discard_bytes(&mut reader, &mut scratch, u64::from(length - 2)).is_err() {
            return 0;
        }
    }
}

fn parse_exif_segment<R: Read>(reader: &mut R, scratch: &mut [u8]) -> u16 {
    let mut header = [0_u8; 6];
    if reader.read_exact(&mut header).is_err() || header != *b"Exif\0\0" {
        return 0;
    }

    let order_marker = match read_u16_be(reader) {
        Some(value) => value,
        None => return 0,
    };
    let order = match order_marker {
        0x4d4d => ByteOrder::Big,
        0x4949 => ByteOrder::Little,
        _ => return 0,
    };
    if read_u16_order(reader, order).unwrap_or_default() != 42 {
        return 0;
    }
    let ifd_offset = match read_u32_order(reader, order) {
        Some(offset) if offset >= 8 => offset,
        _ => return 0,
    };
    if discard_bytes(reader, scratch, u64::from(ifd_offset - 8)).is_err() {
        return 0;
    }
    let num_entries = match read_u16_order(reader, order) {
        Some(num_entries) => num_entries,
        None => return 0,
    };
    for _ in 0..num_entries {
        let tag = match read_u16_order(reader, order) {
            Some(tag) => tag,
            None => return 0,
        };
        if tag != 0x0112 {
            if discard_bytes(reader, scratch, 10).is_err() {
                return 0;
            }
            continue;
        }
        if discard_bytes(reader, scratch, 6).is_err() {
            return 0;
        }
        let orientation = read_u16_order(reader, order).unwrap_or_default();
        return if (1..=8).contains(&orientation) {
            orientation
        } else {
            0
        };
    }
    0
}

fn discard_bytes<R: Read>(reader: &mut R, scratch: &mut [u8], mut n: u64) -> std::io::Result<()> {
    while n > 0 {
        let len = usize::try_from(n.min(scratch.len() as u64)).unwrap_or(scratch.len());
        reader.read_exact(&mut scratch[..len])?;
        n -= len as u64;
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum ByteOrder {
    Big,
    Little,
}

fn read_u16_be<R: Read>(reader: &mut R) -> Option<u16> {
    let mut buf = [0_u8; 2];
    reader.read_exact(&mut buf).ok()?;
    Some(u16::from_be_bytes(buf))
}

fn read_u16_order<R: Read>(reader: &mut R, order: ByteOrder) -> Option<u16> {
    let mut buf = [0_u8; 2];
    reader.read_exact(&mut buf).ok()?;
    Some(match order {
        ByteOrder::Big => u16::from_be_bytes(buf),
        ByteOrder::Little => u16::from_le_bytes(buf),
    })
}

fn read_u32_order<R: Read>(reader: &mut R, order: ByteOrder) -> Option<u32> {
    let mut buf = [0_u8; 4];
    reader.read_exact(&mut buf).ok()?;
    Some(match order {
        ByteOrder::Big => u32::from_be_bytes(buf),
        ByteOrder::Little => u32::from_le_bytes(buf),
    })
}

fn rotate90(img: &DynamicImage) -> DynamicImage {
    let src = img.to_rgba8();
    let (w, h) = src.dimensions();
    let mut out = RgbaImage::new(h, w);
    for y in 0..h {
        for x in 0..w {
            out.put_pixel(h - y - 1, x, *src.get_pixel(x, y));
        }
    }
    DynamicImage::ImageRgba8(out)
}

fn rotate180(img: &DynamicImage) -> DynamicImage {
    let src = img.to_rgba8();
    let (w, h) = src.dimensions();
    let mut out = RgbaImage::new(w, h);
    for y in 0..h {
        for x in 0..w {
            out.put_pixel(w - x - 1, h - y - 1, *src.get_pixel(x, y));
        }
    }
    DynamicImage::ImageRgba8(out)
}

fn rotate270(img: &DynamicImage) -> DynamicImage {
    let src = img.to_rgba8();
    let (w, h) = src.dimensions();
    let mut out = RgbaImage::new(h, w);
    for y in 0..h {
        for x in 0..w {
            out.put_pixel(y, w - x - 1, *src.get_pixel(x, y));
        }
    }
    DynamicImage::ImageRgba8(out)
}

fn mirror_horizontal(img: &DynamicImage) -> DynamicImage {
    let src = img.to_rgba8();
    let (w, h) = src.dimensions();
    let mut out = RgbaImage::new(w, h);
    for y in 0..h {
        for x in 0..w {
            out.put_pixel(w - x - 1, y, *src.get_pixel(x, y));
        }
    }
    DynamicImage::ImageRgba8(out)
}

fn mirror_vertical(img: &DynamicImage) -> DynamicImage {
    let src = img.to_rgba8();
    let (w, h) = src.dimensions();
    let mut out = RgbaImage::new(w, h);
    for y in 0..h {
        for x in 0..w {
            out.put_pixel(x, h - y - 1, *src.get_pixel(x, y));
        }
    }
    DynamicImage::ImageRgba8(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::image::{Rgba, RgbaImage};

    #[test]
    fn parse_orientation_reads_jpeg_exif_orientation() {
        let bytes = jpeg_with_orientation(6);
        assert_eq!(parse_orientation(Cursor::new(bytes)), 6);
    }

    #[test]
    fn parse_orientation_stops_at_app1_segment_boundary() {
        let mut app1 = exif_orientation_entry_prefix();
        let mut bytes = jpeg_with_app1(&app1);
        bytes.extend_from_slice(&6_u16.to_be_bytes());

        assert_eq!(parse_orientation(Cursor::new(bytes)), 0);

        app1.extend_from_slice(&6_u16.to_be_bytes());
        assert_eq!(parse_orientation(Cursor::new(jpeg_with_app1(&app1))), 6);
    }

    #[test]
    fn orientation_rotates_image_like_go() {
        let img = DynamicImage::ImageRgba8({
            let mut img = RgbaImage::new(2, 1);
            img.put_pixel(0, 0, Rgba([1, 0, 0, 255]));
            img.put_pixel(1, 0, Rgba([2, 0, 0, 255]));
            img
        });
        let rotated = rotate90(&img).to_rgba8();
        assert_eq!(rotated.dimensions(), (1, 2));
        assert_eq!(rotated.get_pixel(0, 0)[0], 1);
        assert_eq!(rotated.get_pixel(0, 1)[0], 2);
    }

    fn jpeg_with_orientation(orientation: u16) -> Vec<u8> {
        let mut app1 = exif_orientation_entry_prefix();
        app1.extend_from_slice(&orientation.to_be_bytes());
        app1.extend_from_slice(&0_u16.to_be_bytes());
        jpeg_with_app1(&app1)
    }

    fn jpeg_with_app1(app1: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0xffd8_u16.to_be_bytes());
        bytes.extend_from_slice(&0xffe1_u16.to_be_bytes());
        bytes.extend_from_slice(&u16::try_from(app1.len() + 2).unwrap().to_be_bytes());
        bytes.extend_from_slice(app1);
        bytes
    }

    fn exif_orientation_entry_prefix() -> Vec<u8> {
        let mut app1 = Vec::new();
        app1.extend_from_slice(b"Exif\0\0");
        app1.extend_from_slice(&0x4d4d_u16.to_be_bytes());
        app1.extend_from_slice(&42_u16.to_be_bytes());
        app1.extend_from_slice(&8_u32.to_be_bytes());
        app1.extend_from_slice(&1_u16.to_be_bytes());
        app1.extend_from_slice(&0x0112_u16.to_be_bytes());
        app1.extend_from_slice(&3_u16.to_be_bytes());
        app1.extend_from_slice(&1_u32.to_be_bytes());
        app1
    }
}
