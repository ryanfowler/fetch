use std::{
    cmp,
    io::{self, Cursor},
};

use image::{load_from_memory_with_format, DynamicImage, GenericImageView, ImageFormat};

use emulator::Emulator;

mod block;
mod emulator;
mod inline;
mod kitty;

#[derive(Copy, Clone, Debug)]
enum Protocol {
    Block,
    InlineImages,
    Kitty,
}

pub(crate) struct Image {
    img: DynamicImage,
}

impl Image {
    pub(crate) fn new(input: &[u8]) -> Option<Image> {
        Self::new_inner(input).map(|img| Image { img })
    }

    pub(crate) fn dynamic_image(&self) -> &DynamicImage {
        &self.img
    }

    pub(crate) fn write_to_stdout(self) -> std::io::Result<()> {
        // If any of the image's dimensions are zero, return immediately.
        let (width, height) = self.img.dimensions();
        if width == 0 || height == 0 {
            return Ok(());
        }

        let emulator = Emulator::detect();
        match emulator.supported_protocol() {
            Protocol::Block => block::write_to_stdout(self),
            Protocol::InlineImages => inline::write_to_stdout(self),
            Protocol::Kitty => kitty::write_to_stdout(self),
        }
    }

    pub(crate) fn dimensions(&self) -> (u32, u32) {
        self.img.dimensions()
    }

    pub(crate) fn resize_for_term(self) -> Self {
        Self {
            img: resize_for_term(self.img),
        }
    }

    fn new_inner(input: &[u8]) -> Option<DynamicImage> {
        Self::get_format(input)
            .and_then(|format| match format {
                ImageFormat::Jpeg => Some(load_from_memory_with_format(input, format).ok()?),
                ImageFormat::Png => Some(load_from_memory_with_format(input, format).ok()?),
                ImageFormat::Tiff => Some(load_from_memory_with_format(input, format).ok()?),
                ImageFormat::WebP => {
                    Some(webp::Decoder::new(input).decode().map(|v| v.to_image())?)
                }
                _ => None,
            })
            .map(|img| {
                let orientation = Self::get_orientation(input);
                Self::auto_orient(orientation, img)
            })
    }

    fn get_format(input: &[u8]) -> Option<ImageFormat> {
        if input.len() < 12 {
            return None;
        }

        const JPEG: &[u8; 3] = b"\xFF\xD8\xFF";
        if input.starts_with(JPEG) {
            return Some(ImageFormat::Jpeg);
        }

        const PNG: &[u8; 4] = b"\x89\x50\x4E\x47";
        if input.starts_with(PNG) {
            return Some(ImageFormat::Png);
        }

        const TIFFII: &[u8; 4] = b"\x49\x49\x2A\x00";
        const TIFFMM: &[u8; 4] = b"\x4D\x4D\x00\x2A";
        if input.starts_with(TIFFII) || input.starts_with(TIFFMM) {
            return Some(ImageFormat::Tiff);
        }

        const WEBP: &[u8; 4] = b"\x57\x45\x42\x50";
        if input[8..].starts_with(WEBP) {
            return Some(ImageFormat::WebP);
        }

        None
    }

    fn auto_orient(orientation: Option<u32>, img: DynamicImage) -> DynamicImage {
        if let Some(orientation) = orientation {
            return match orientation {
                2 => img.fliph(),
                3 => img.rotate180(),
                4 => img.flipv(),
                5 => img.rotate90().fliph(),
                6 => img.rotate90(),
                7 => img.rotate270().fliph(),
                8 => img.rotate270(),
                _ => img,
            };
        }
        img
    }

    fn get_orientation(input: &[u8]) -> Option<u32> {
        let mut cursor = Cursor::new(input);
        exif::Reader::new()
            .read_from_container(&mut cursor)
            .ok()
            .and_then(|data| {
                data.get_field(exif::Tag::Orientation, exif::In::PRIMARY)
                    .and_then(|field| field.value.get_uint(0))
            })
    }
}

// Use only 4/5ths of the height of the terminal.
static NUMERATOR: u32 = 4;
static DENOMINATOR: u32 = 5;

fn resize_for_term(img: DynamicImage) -> DynamicImage {
    let size = match crossterm::terminal::window_size() {
        Err(_) => return img,
        Ok(size) => size,
    };
    if size.width == 0 || size.height == 0 {
        return img;
    }

    let t_width = size.width as u32;
    let t_height = (size.height as u32) * NUMERATOR / DENOMINATOR;
    let (width, height) = img.dimensions();

    if width <= t_width && height <= t_height {
        return img;
    }

    let aspect_ratio = width as f32 / height as f32;
    let t_aspect_ratio = t_width as f32 / t_height as f32;
    let (w, h) = if aspect_ratio > t_aspect_ratio {
        (t_width, (t_width as f32 / aspect_ratio) as u32)
    } else {
        ((t_height as f32 * aspect_ratio) as u32, t_height)
    };

    img.thumbnail(w, h)
}

fn image_block_output_dimensions(img: &DynamicImage) -> io::Result<(u32, u32)> {
    let size = crossterm::terminal::size()?;
    let cols = size.0 as u32;
    let rows = 2 * size.1 as u32 * NUMERATOR / DENOMINATOR;

    let (width, height) = img.dimensions();
    Ok(dimensions_for_sizes(cols, rows, width, height))
}

fn dimensions_for_sizes(cols: u32, rows: u32, width: u32, height: u32) -> (u32, u32) {
    // If image is smaller than bounds, return the scaled image dimensions.
    if width <= cols && height <= rows {
        return (width, height / 2 + height % 2);
    }

    // Otherwise calculate appropriate size.
    if cols * height <= width * rows {
        (cols, cmp::max(1, height * cols / width / 2))
    } else {
        (width * rows / height, cmp::max(1, rows / 2))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_dims_for_sizes() {
        let size = dimensions_for_sizes(40, 30, 100, 100);
        assert_eq!(size, (30, 15));
    }
}
