use std::{
    cmp, env,
    io::{self, Cursor},
};

use crossterm::terminal::WindowSize;
use image::{load_from_memory_with_format, DynamicImage, GenericImageView, ImageFormat};

mod block;
mod inline;
mod kitty;

#[derive(Copy, Clone, Debug)]
enum Protocol {
    Block,
    InlineImages,
    Kitty,
}

#[derive(Copy, Clone, Debug)]
enum Emulator {
    Alacritty,
    Apple,
    Ghostty,
    Hyper,
    Iterm2,
    Kitty,
    Konsole,
    Mintty,
    Unknown,
    VSCode,
    WezTerm,
    Windows,
}

impl Emulator {
    fn detect() -> Self {
        if let Some(emulator) = Self::detect_term_program_var() {
            return emulator;
        }

        if let Some(emulator) = Self::detect_term_var() {
            return emulator;
        }

        if let Some(emulator) = Self::detect_custom_var() {
            return emulator;
        }

        Self::Unknown
    }

    fn detect_term_program_var() -> Option<Emulator> {
        let values = [
            ("Apple_Terminal", Self::Apple),
            ("ghostty", Self::Ghostty),
            ("Hyper", Self::Hyper),
            ("iTerm.app", Self::Iterm2),
            ("mintty", Self::Mintty),
            ("vscode", Self::VSCode),
            ("WezTerm", Self::WezTerm),
        ];

        if let Ok(var) = env::var("TERM_PROGRAM") {
            for (value, emulator) in values.into_iter() {
                if var.as_str() == value {
                    return Some(emulator);
                }
            }
        }

        None
    }

    fn detect_term_var() -> Option<Emulator> {
        let values = [
            ("alacritty", Self::Alacritty),
            ("xterm-ghostty", Self::Ghostty),
            ("xterm-kitty", Self::Kitty),
        ];

        if let Ok(var) = env::var("TERM") {
            for (value, emulator) in values.into_iter() {
                if var.as_str() == value {
                    return Some(emulator);
                }
            }
        }
        None
    }

    fn detect_custom_var() -> Option<Emulator> {
        let values = [
            ("GHOSTTY_BIN_DIR", Self::Ghostty),
            ("ITERM_SESSION_ID", Self::Iterm2),
            ("KITTY_PID", Self::Kitty),
            ("KONSOLE_VERSION", Self::Konsole),
            ("VSCODE_INJECTION", Self::VSCode),
            ("WEZTERM_EXECUTABLE", Self::WezTerm),
            ("WT_SESSION", Self::Windows),
        ];

        for (var, emulator) in values.into_iter() {
            if env::var_os(var).is_some() {
                return Some(emulator);
            }
        }
        None
    }

    fn supported_protocol(&self) -> Protocol {
        match self {
            Emulator::Alacritty => Protocol::Block,
            Emulator::Apple => Protocol::Block,
            Emulator::Ghostty => Protocol::Kitty,
            Emulator::Hyper => Protocol::InlineImages,
            Emulator::Iterm2 => Protocol::InlineImages,
            Emulator::Kitty => Protocol::Kitty,
            Emulator::Konsole => Protocol::Kitty,
            Emulator::Mintty => Protocol::InlineImages,
            Emulator::Unknown => Protocol::Block,
            Emulator::VSCode => Protocol::InlineImages,
            Emulator::WezTerm => Protocol::InlineImages,
            Emulator::Windows => Protocol::Block,
        }
    }
}

pub(crate) struct Image {
    img: DynamicImage,
}

impl Image {
    pub(crate) fn new(input: &[u8]) -> Option<Image> {
        Self::new_inner(input).map(|img| Image { img })
    }

    pub(crate) fn write_to_stdout(&self) -> std::io::Result<()> {
        let emulator = Emulator::detect();
        match emulator.supported_protocol() {
            Protocol::Block => block::write_to_stdout(&self.img),
            Protocol::InlineImages => inline::write_to_stdout(&self.img),
            Protocol::Kitty => kitty::write_to_stdout(&self.img),
        }
    }

    fn new_inner(input: &[u8]) -> Option<DynamicImage> {
        Self::get_format(input)
            .and_then(|format| match format {
                ImageFormat::Avif => Some(libavif_image::read(input).ok()?),
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

        const AVIF: &[u8; 8] = b"ftypavif";
        if input[4..].starts_with(AVIF) {
            return Some(ImageFormat::Avif);
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

fn image_output_dimensions(img: &DynamicImage) -> io::Result<(u32, u32)> {
    let (width, height) = img.dimensions();
    let size = get_term_dimensions()?;
    let cols = size.columns as u32;
    let rows = 2 * size.rows as u32 * NUMERATOR / DENOMINATOR;

    // Use pixel count to size image appropriately.
    let t_width = size.width as u32;
    let t_height = size.height as u32 * NUMERATOR / DENOMINATOR;
    if t_width > 0 && t_height > 0 && (height < t_height || width < t_width) {
        let (cell_width, cell_height) = (t_width / cols, t_height / rows);
        let mut icols = width / cell_width;
        let mut irows = height / cell_height;

        if icols > cols {
            icols = cols;
            irows = (height as f32 / width as f32 * cols as f32) as u32;
        }
        if irows > rows {
            irows = rows;
            icols = (width as f32 / height as f32 * rows as f32) as u32;
        }
        return Ok((icols, irows / 2));
    }

    Ok(dimensions_for_sizes(cols, rows, width, height))
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

fn get_term_dimensions() -> io::Result<WindowSize> {
    crossterm::terminal::window_size().or_else(|_| {
        crossterm::terminal::size().map(|size| WindowSize {
            columns: size.0,
            rows: size.1,
            width: 0,
            height: 0,
        })
    })
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
