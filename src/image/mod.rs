use std::env;
use std::fmt;
use std::io::{Cursor, Read};
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use ::image::codecs::png::PngEncoder;
use ::image::imageops::FilterType;
use ::image::{ColorType, DynamicImage, GenericImageView, ImageEncoder, Rgba, RgbaImage};
use base64::Engine;

#[derive(Debug, thiserror::Error)]
pub enum ImageError {
    #[error("{0}")]
    Message(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Decode(#[from] ::image::ImageError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Protocol {
    Block,
    Inline,
    Kitty,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Emulator {
    Unknown,
    Alacritty,
    Apple,
    Ghostty,
    Hyper,
    Iterm2,
    Kitty,
    Konsole,
    Mintty,
    Tmux,
    Vscode,
    WezTerm,
    Windows,
    Zellij,
}

impl Emulator {
    fn protocol(self) -> Protocol {
        match self {
            Self::Alacritty
            | Self::Apple
            | Self::Tmux
            | Self::Unknown
            | Self::Vscode
            | Self::Windows
            | Self::Zellij => Protocol::Block,
            Self::Hyper | Self::Iterm2 | Self::Mintty | Self::WezTerm => Protocol::Inline,
            Self::Ghostty | Self::Kitty | Self::Konsole => Protocol::Kitty,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TerminalSize {
    cols: u32,
    rows: u32,
    width_px: u32,
    height_px: u32,
}

#[derive(Debug, Clone, Copy)]
struct RenderOptions {
    size: TerminalSize,
    protocol: Protocol,
    true_color: bool,
}

pub fn render(bytes: &[u8], native_only: bool) -> Result<Vec<u8>, ImageError> {
    let size = terminal_size()?;
    let protocol = if size.width_px == 0 || size.height_px == 0 {
        Protocol::Block
    } else {
        detect_emulator().protocol()
    };
    let options = RenderOptions {
        size,
        protocol,
        true_color: supports_true_color(),
    };
    render_with_options(bytes, native_only, options)
}

fn render_with_options(
    bytes: &[u8],
    native_only: bool,
    options: RenderOptions,
) -> Result<Vec<u8>, ImageError> {
    let img = orient_image(bytes, decode_image(bytes, native_only)?);
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

fn decode_image(bytes: &[u8], native_only: bool) -> Result<DynamicImage, ImageError> {
    match decode_image_std(bytes) {
        Ok(img) => Ok(img),
        Err(err) if native_only => Err(err),
        Err(err) => decode_with_adaptors(bytes).or(Err(err)),
    }
}

fn decode_image_std(bytes: &[u8]) -> Result<DynamicImage, ImageError> {
    const LIMIT: u32 = 8192;
    let img = ::image::load_from_memory(bytes)?;
    let (width, height) = img.dimensions();
    if width > LIMIT || height > LIMIT {
        return Err(ImageError::Message(format!(
            "image dimensions are too large {width}x{height}"
        )));
    }
    Ok(img)
}

#[derive(Clone, Copy)]
struct Adaptor {
    name: &'static str,
    args: &'static [&'static str],
    env: &'static [(&'static str, &'static str)],
}

const IMAGE_PATH_ARG: &str = "IMAGE_PATH";
const ADAPTORS: &[Adaptor] = &[
    Adaptor {
        name: "vips",
        args: &["copy", IMAGE_PATH_ARG, ".jpeg"],
        env: &[("VIPS_MAX_MEM", "512MB")],
    },
    Adaptor {
        name: "magick",
        args: &[IMAGE_PATH_ARG, "-flatten", "-auto-orient", "jpeg:-"],
        env: &[("MAGICK_MEMORY_LIMIT", "512MiB")],
    },
    Adaptor {
        name: "ffmpeg",
        args: &[
            "-i",
            IMAGE_PATH_ARG,
            "-f",
            "image2pipe",
            "-vcodec",
            "mjpeg",
            "pipe:1",
        ],
        env: &[],
    },
];

fn decode_with_adaptors(bytes: &[u8]) -> Result<DynamicImage, ImageError> {
    let dir = TempImageDir::create()?;
    let image_path = dir.path.join("fetch-temp-image");
    std::fs::write(&image_path, bytes)?;

    for adaptor in ADAPTORS {
        if let Ok(img) = decode_adaptor(&image_path, *adaptor) {
            return Ok(img);
        }
    }
    Err(ImageError::Message("unable to decode image".to_string()))
}

fn decode_adaptor(path: &std::path::Path, adaptor: Adaptor) -> Result<DynamicImage, ImageError> {
    let mut cmd = Command::new(adaptor.name);
    for arg in adaptor.args {
        if *arg == IMAGE_PATH_ARG {
            cmd.arg(path);
        } else {
            cmd.arg(arg);
        }
    }
    for (key, value) in adaptor.env {
        cmd.env(key, value);
    }
    let output = cmd.output()?;
    if !output.status.success() {
        return Err(ImageError::Message(format!(
            "{} exited with {}",
            adaptor.name, output.status
        )));
    }
    decode_image_std(&output.stdout)
}

struct TempImageDir {
    path: PathBuf,
}

impl TempImageDir {
    fn create() -> std::io::Result<Self> {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = env::temp_dir().join(format!("fetch-image-{}-{stamp}", std::process::id()));
        std::fs::create_dir(&path)?;
        Ok(Self { path })
    }
}

impl Drop for TempImageDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn write_blocks(
    img: &DynamicImage,
    term_width: u32,
    term_height: u32,
    true_color: bool,
) -> Vec<u8> {
    let (cols, rows) = image_block_output_dimensions(img, term_width, term_height);
    let target_width = cols.max(1);
    let target_height = (rows * 2).max(1);
    let dst = resize_image(img, target_width, target_height);

    let mut out = String::new();
    for row in 0..rows {
        let top_y = row * 2;
        let bottom_y = top_y + 1;
        for x in 0..cols {
            let top = pixel_to_color(dst.get_pixel(x, top_y));
            let bottom = if bottom_y < target_height {
                pixel_to_color(dst.get_pixel(x, bottom_y))
            } else {
                None
            };
            write_block(&mut out, top, bottom, true_color);
        }
        out.push('\n');
    }
    out.push_str("\x1b[0m");
    out.into_bytes()
}

fn image_block_output_dimensions(
    img: &DynamicImage,
    term_width: u32,
    term_height: u32,
) -> (u32, u32) {
    let cols = term_width.max(1);
    let rows = (2 * term_height * 4 / 5).max(1);
    let (width, height) = img.dimensions();
    if width <= cols && height <= rows {
        return (width.max(1), (height / 2 + height % 2).max(1));
    }
    if cols.saturating_mul(height) <= width.saturating_mul(rows) {
        return (cols, ((height * cols) / width / 2).max(1));
    }
    (((width * rows) / height).max(1), (rows / 2).max(1))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RgbColor {
    r: u8,
    g: u8,
    b: u8,
}

fn pixel_to_color(pixel: Rgba<u8>) -> Option<RgbColor> {
    if pixel[3] == 0 {
        return None;
    }
    Some(RgbColor {
        r: pixel[0],
        g: pixel[1],
        b: pixel[2],
    })
}

fn write_block(
    out: &mut String,
    top: Option<RgbColor>,
    bottom: Option<RgbColor>,
    true_color: bool,
) {
    match (top, bottom) {
        (None, None) => out.push(' '),
        (Some(top), None) => {
            ansi_fg(out, top, true_color);
            out.push('▀');
            out.push_str("\x1b[0m");
        }
        (None, Some(bottom)) => {
            ansi_fg(out, bottom, true_color);
            out.push('▄');
            out.push_str("\x1b[0m");
        }
        (Some(top), Some(bottom)) => {
            ansi_bg(out, top, true_color);
            ansi_fg(out, bottom, true_color);
            out.push('▄');
            out.push_str("\x1b[0m");
        }
    }
}

fn ansi_fg(out: &mut String, color: RgbColor, true_color: bool) {
    if true_color {
        fmt::Write::write_fmt(
            out,
            format_args!("\x1b[38;2;{};{};{}m", color.r, color.g, color.b),
        )
        .expect("writing to String cannot fail");
    } else {
        fmt::Write::write_fmt(
            out,
            format_args!("\x1b[38;5;{}m", ansi256_from_rgb(color.r, color.g, color.b)),
        )
        .expect("writing to String cannot fail");
    }
}

fn ansi_bg(out: &mut String, color: RgbColor, true_color: bool) {
    if true_color {
        fmt::Write::write_fmt(
            out,
            format_args!("\x1b[48;2;{};{};{}m", color.r, color.g, color.b),
        )
        .expect("writing to String cannot fail");
    } else {
        fmt::Write::write_fmt(
            out,
            format_args!("\x1b[48;5;{}m", ansi256_from_rgb(color.r, color.g, color.b)),
        )
        .expect("writing to String cannot fail");
    }
}

fn ansi256_from_rgb(r: u8, g: u8, b: u8) -> u8 {
    if r == g && g == b {
        if r < 8 {
            return 16;
        }
        if r > 248 {
            return 231;
        }
        return ((r - 8) / 10) + 232;
    }
    let red = r as u16 * 5 / 255;
    let green = g as u16 * 5 / 255;
    let blue = b as u16 * 5 / 255;
    (16 + 36 * red + 6 * green + blue) as u8
}

fn write_inline(
    img: &DynamicImage,
    term_width_px: u32,
    term_height_px: u32,
) -> Result<Vec<u8>, ImageError> {
    let img = resize_for_term(img, term_width_px, term_height_px);
    let data = encode_to_base64_png(&img)?;
    Ok(format!(
        "\x1b]1337;File=inline=1;preserveAspectRatio=1;size={};width={}px;height={}px:{}\x07\n",
        data.len(),
        img.width(),
        img.height(),
        data
    )
    .into_bytes())
}

fn write_kitty(
    img: &DynamicImage,
    term_width_px: u32,
    term_height_px: u32,
) -> Result<Vec<u8>, ImageError> {
    let img = resize_for_term(img, term_width_px, term_height_px);
    let data = encode_to_base64_png(&img)?;
    let mut out = String::new();
    let mut next = data.len().min(4096);
    fmt::Write::write_fmt(
        &mut out,
        format_args!(
            "\x1b_Gq=2,f=100,a=T,t=d,s={},v={},m={};{}\x1b\\",
            img.width(),
            img.height(),
            bool_to_int(next < data.len()),
            &data[..next]
        ),
    )
    .expect("writing to String cannot fail");
    let mut pos = next;
    while pos < data.len() {
        next = (pos + 4096).min(data.len());
        fmt::Write::write_fmt(
            &mut out,
            format_args!(
                "\x1b_Gm={};{}\x1b\\",
                bool_to_int(next < data.len()),
                &data[pos..next]
            ),
        )
        .expect("writing to String cannot fail");
        pos = next;
    }
    out.push('\n');
    Ok(out.into_bytes())
}

fn bool_to_int(value: bool) -> u8 {
    u8::from(value)
}

fn resize_for_term(img: &DynamicImage, term_width_px: u32, term_height_px: u32) -> DynamicImage {
    if term_width_px == 0 || term_height_px == 0 {
        return img.clone();
    }

    let term_height_px = (term_height_px * 4 / 5).max(1);
    let (width, height) = img.dimensions();
    if width <= term_width_px && height <= term_height_px {
        return img.clone();
    }

    let aspect_ratio = width as f64 / height as f64;
    let term_aspect_ratio = term_width_px as f64 / term_height_px as f64;
    if aspect_ratio > term_aspect_ratio {
        let h = ((term_width_px as f64) / aspect_ratio).floor().max(1.0) as u32;
        resize_image(img, term_width_px.max(1), h)
    } else {
        let w = ((term_height_px as f64) * aspect_ratio).floor().max(1.0) as u32;
        resize_image(img, w, term_height_px)
    }
}

fn resize_image(img: &DynamicImage, width: u32, height: u32) -> DynamicImage {
    DynamicImage::ImageRgba8(::image::imageops::resize(
        &img.to_rgba8(),
        width,
        height,
        FilterType::Triangle,
    ))
}

fn encode_to_base64_png(img: &DynamicImage) -> Result<String, ImageError> {
    let rgba = img.to_rgba8();
    let mut png = Vec::new();
    PngEncoder::new(&mut png).write_image(
        rgba.as_raw(),
        rgba.width(),
        rgba.height(),
        ColorType::Rgba8.into(),
    )?;
    Ok(base64::engine::general_purpose::STANDARD.encode(png))
}

fn orient_image(bytes: &[u8], img: DynamicImage) -> DynamicImage {
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
            let mut segment = reader.take(length as u64);
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

fn supports_true_color() -> bool {
    supports_true_color_with_env(|name| env::var(name).ok(), cfg!(windows))
}

fn supports_true_color_with_env(get: impl Fn(&str) -> Option<String>, is_windows: bool) -> bool {
    let colorterm = get("COLORTERM").unwrap_or_default();
    colorterm.eq_ignore_ascii_case("truecolor")
        || colorterm.eq_ignore_ascii_case("24bit")
        || (is_windows
            && (get_non_empty(&get, "WT_SESSION").is_some()
                || get("ConEmuANSI").as_deref() == Some("ON")))
}

fn detect_emulator() -> Emulator {
    detect_emulator_with_env(|name| env::var(name).ok())
}

fn detect_emulator_with_env(get: impl Fn(&str) -> Option<String> + Copy) -> Emulator {
    if get_non_empty(&get, "ZELLIJ").is_some() {
        return Emulator::Zellij;
    }
    detect_program_var(get)
        .or_else(|| detect_term_var(get))
        .or_else(|| detect_custom_var(get))
        .unwrap_or(Emulator::Unknown)
}

fn get_non_empty(get: &impl Fn(&str) -> Option<String>, name: &str) -> Option<String> {
    get(name).filter(|value| !value.is_empty())
}

fn detect_program_var(get: impl Fn(&str) -> Option<String>) -> Option<Emulator> {
    match get("TERM_PROGRAM").as_deref() {
        Some("Apple_Terminal") => Some(Emulator::Apple),
        Some("ghostty") => Some(Emulator::Ghostty),
        Some("Hyper") => Some(Emulator::Hyper),
        Some("iTerm.app") => Some(Emulator::Iterm2),
        Some("mintty") => Some(Emulator::Mintty),
        Some("tmux") => Some(Emulator::Tmux),
        Some("vscode") => Some(Emulator::Vscode),
        Some("WezTerm") => Some(Emulator::WezTerm),
        _ => None,
    }
}

fn detect_term_var(get: impl Fn(&str) -> Option<String>) -> Option<Emulator> {
    match get("TERM").as_deref() {
        Some("alacritty") => Some(Emulator::Alacritty),
        Some("xterm-ghostty") => Some(Emulator::Ghostty),
        Some("xterm-kitty") => Some(Emulator::Kitty),
        _ => None,
    }
}

fn detect_custom_var(get: impl Fn(&str) -> Option<String>) -> Option<Emulator> {
    if get_non_empty(&get, "GHOSTTY_BIN_DIR").is_some() {
        Some(Emulator::Ghostty)
    } else if get_non_empty(&get, "ITERM_SESSION_ID").is_some() {
        Some(Emulator::Iterm2)
    } else if get_non_empty(&get, "KITTY_PID").is_some() {
        Some(Emulator::Kitty)
    } else if get_non_empty(&get, "KONSOLE_VERSION").is_some() {
        Some(Emulator::Konsole)
    } else if get_non_empty(&get, "VSCODE_INJECTION").is_some() {
        Some(Emulator::Vscode)
    } else if get_non_empty(&get, "WEZTERM_EXECUTABLE").is_some() {
        Some(Emulator::WezTerm)
    } else if get_non_empty(&get, "WT_SESSION").is_some() {
        Some(Emulator::Windows)
    } else {
        None
    }
}

#[cfg(unix)]
fn terminal_size() -> std::io::Result<TerminalSize> {
    let mut ws = std::mem::MaybeUninit::<libc::winsize>::zeroed();
    let rc = unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, ws.as_mut_ptr()) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let ws = unsafe { ws.assume_init() };
    Ok(TerminalSize {
        cols: u32::from(ws.ws_col),
        rows: u32::from(ws.ws_row),
        width_px: u32::from(ws.ws_xpixel),
        height_px: u32::from(ws.ws_ypixel),
    })
}

#[cfg(not(unix))]
fn terminal_size() -> std::io::Result<TerminalSize> {
    let cols = env::var("COLUMNS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    let rows = env::var("LINES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    if cols == 0 || rows == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "terminal size unavailable",
        ));
    }
    Ok(TerminalSize {
        cols,
        rows,
        width_px: 0,
        height_px: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn image_block_dimensions_match_go_scaling_rules() {
        let img = DynamicImage::ImageRgba8(RgbaImage::new(10, 4));
        assert_eq!(image_block_output_dimensions(&img, 80, 24), (10, 2));

        let wide = DynamicImage::ImageRgba8(RgbaImage::new(400, 100));
        assert_eq!(image_block_output_dimensions(&wide, 80, 24), (80, 10));

        let tall = DynamicImage::ImageRgba8(RgbaImage::new(100, 400));
        assert_eq!(image_block_output_dimensions(&tall, 80, 24), (9, 19));
    }

    #[test]
    fn ansi256_from_rgb_matches_go_boundaries() {
        assert_eq!(ansi256_from_rgb(0, 0, 0), 16);
        assert_eq!(ansi256_from_rgb(255, 255, 255), 231);
        assert_eq!(ansi256_from_rgb(128, 128, 128), 244);
        assert_eq!(ansi256_from_rgb(255, 0, 0), 196);
    }

    #[test]
    fn write_blocks_uses_foreground_and_background_colors() {
        let out = String::from_utf8(write_blocks(&img_1x2(), 1, 1, true)).unwrap();
        assert_eq!(out, "\x1b[48;2;255;0;0m\x1b[38;2;0;0;255m▄\x1b[0m\n\x1b[0m");
    }

    #[test]
    fn supports_true_color_matches_go_environment_policy() {
        let env = |pairs: &[(&str, &str)], is_windows| {
            supports_true_color_with_env(
                |name| {
                    pairs
                        .iter()
                        .find_map(|(key, value)| (*key == name).then(|| (*value).to_string()))
                },
                is_windows,
            )
        };

        assert!(env(&[("COLORTERM", "truecolor")], false));
        assert!(env(&[("COLORTERM", "24bit")], false));
        assert!(env(&[("COLORTERM", "TRUECOLOR")], false));
        assert!(!env(&[("COLORTERM", "256color")], false));
        assert!(!env(&[("WT_SESSION", "1")], false));
        assert!(!env(&[("ConEmuANSI", "ON")], false));
        assert!(env(&[("WT_SESSION", "1")], true));
        assert!(!env(&[("WT_SESSION", "")], true));
        assert!(env(&[("ConEmuANSI", "ON")], true));
        assert!(!env(&[("ConEmuANSI", "on")], true));
    }

    #[test]
    fn detect_emulator_ignores_empty_environment_values() {
        let pairs = [
            ("TERM", "xterm-kitty"),
            ("TERM_PROGRAM", ""),
            ("ZELLIJ", ""),
            ("GHOSTTY_BIN_DIR", ""),
            ("ITERM_SESSION_ID", ""),
            ("KITTY_PID", ""),
            ("KONSOLE_VERSION", ""),
            ("VSCODE_INJECTION", ""),
            ("WEZTERM_EXECUTABLE", ""),
            ("WT_SESSION", ""),
        ];
        let get = |name: &str| -> Option<String> {
            pairs
                .iter()
                .find_map(|(key, value)| (*key == name).then(|| (*value).to_string()))
        };

        assert_eq!(detect_emulator_with_env(get), Emulator::Kitty);
    }

    #[test]
    fn inline_and_kitty_protocols_emit_expected_escape_sequences() {
        let img = img_1x2();
        let inline = String::from_utf8(write_inline(&img, 20, 20).unwrap()).unwrap();
        assert!(inline.starts_with("\x1b]1337;File=inline=1;preserveAspectRatio=1;"));
        assert!(inline.ends_with("\x07\n"));

        let kitty = String::from_utf8(write_kitty(&img, 20, 20).unwrap()).unwrap();
        assert!(kitty.starts_with("\x1b_Gq=2,f=100,a=T,t=d,s=1,v=2,m=0;"));
        assert!(kitty.ends_with("\x1b\\\n"));
    }

    #[test]
    fn render_with_options_decodes_png_and_renders_blocks() {
        let bytes = png_bytes(&img_1x2());
        let out = render_with_options(
            &bytes,
            true,
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

    #[test]
    fn parse_orientation_reads_jpeg_exif_orientation() {
        let bytes = jpeg_with_orientation(6);
        assert_eq!(parse_orientation(Cursor::new(bytes)), 6);
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

    #[test]
    fn emulator_detection_protocol_mapping_matches_go() {
        assert_eq!(Emulator::Iterm2.protocol(), Protocol::Inline);
        assert_eq!(Emulator::WezTerm.protocol(), Protocol::Inline);
        assert_eq!(Emulator::Kitty.protocol(), Protocol::Kitty);
        assert_eq!(Emulator::Ghostty.protocol(), Protocol::Kitty);
        assert_eq!(Emulator::Apple.protocol(), Protocol::Block);
    }

    fn jpeg_with_orientation(orientation: u16) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0xffd8_u16.to_be_bytes());
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
        bytes.extend_from_slice(&0xffe1_u16.to_be_bytes());
        bytes.extend_from_slice(&u16::try_from(app1.len() + 2).unwrap().to_be_bytes());
        bytes.extend_from_slice(&app1);
        bytes
    }
}
