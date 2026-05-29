use std::env;
use std::fmt;
use std::io::{Cursor, ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ::image::codecs::png::PngEncoder;
use ::image::imageops::FilterType;
use ::image::{ColorType, DynamicImage, GenericImageView, ImageEncoder, Rgba, RgbaImage};
use base64::Engine;

const IMAGE_DIMENSION_LIMIT: u32 = 8192;
const IMAGE_DECODE_MAX_ALLOC_BYTES: u64 =
    IMAGE_DIMENSION_LIMIT as u64 * IMAGE_DIMENSION_LIMIT as u64 * 4;
const TEMP_IMAGE_DIR_CREATE_ATTEMPTS: u32 = 100;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeMode {
    BuiltIn,
    External,
}

pub fn render(bytes: &[u8], decode_mode: DecodeMode) -> Result<Vec<u8>, ImageError> {
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

fn decode_image(bytes: &[u8], decode_mode: DecodeMode) -> Result<DynamicImage, ImageError> {
    match decode_image_std(bytes) {
        Ok(img) => Ok(img),
        Err(err) if decode_mode == DecodeMode::BuiltIn => Err(err),
        Err(err) => decode_with_adaptors(bytes).or(Err(err)),
    }
}

fn decode_image_std(bytes: &[u8]) -> Result<DynamicImage, ImageError> {
    let mut reader = ::image::ImageReader::new(Cursor::new(bytes)).with_guessed_format()?;
    reader.limits(image_decode_limits());
    let img = reader.decode()?;
    let (width, height) = img.dimensions();
    if width > IMAGE_DIMENSION_LIMIT || height > IMAGE_DIMENSION_LIMIT {
        return Err(ImageError::Message(format!(
            "image dimensions are too large {width}x{height}"
        )));
    }
    Ok(img)
}

fn image_decode_limits() -> ::image::Limits {
    let mut limits = ::image::Limits::default();
    limits.max_image_width = Some(IMAGE_DIMENSION_LIMIT);
    limits.max_image_height = Some(IMAGE_DIMENSION_LIMIT);
    limits.max_alloc = Some(IMAGE_DECODE_MAX_ALLOC_BYTES);
    limits
}

#[derive(Clone, Copy)]
struct Adaptor {
    name: &'static str,
    args: &'static [&'static str],
    env: &'static [(&'static str, &'static str)],
}

const IMAGE_PATH_ARG: &str = "IMAGE_PATH";
const ADAPTOR_TIMEOUT: Duration = Duration::from_secs(10);
const ADAPTOR_STDOUT_CAP: usize = 64 * 1024 * 1024;
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
            "-nostdin",
            "-hide_banner",
            "-loglevel",
            "error",
            "-protocol_whitelist",
            "file,pipe",
            "-i",
            IMAGE_PATH_ARG,
            "-frames:v",
            "1",
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
    write_temp_image_file(&image_path, bytes)?;

    for adaptor in ADAPTORS {
        if let Ok(img) = decode_adaptor(&image_path, *adaptor) {
            return Ok(img);
        }
    }
    Err(ImageError::Message("unable to decode image".to_string()))
}

fn decode_adaptor(path: &Path, adaptor: Adaptor) -> Result<DynamicImage, ImageError> {
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
    let output = run_adaptor(cmd, adaptor.name)?;
    if !output.status.success() {
        return Err(ImageError::Message(format!(
            "{} exited with {}",
            adaptor.name, output.status
        )));
    }
    if output.stdout_truncated {
        return Err(ImageError::Message(format!(
            "{} produced more than {} bytes",
            adaptor.name, ADAPTOR_STDOUT_CAP
        )));
    }
    decode_image_std(&output.stdout)
}

struct AdaptorOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stdout_truncated: bool,
}

fn run_adaptor(mut cmd: Command, name: &str) -> Result<AdaptorOutput, ImageError> {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = cmd.spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| ImageError::Message(format!("{name} stdout unavailable")))?;
    let stdout_reader = thread::spawn(move || read_capped(stdout, ADAPTOR_STDOUT_CAP));
    let deadline = Instant::now() + ADAPTOR_TIMEOUT;

    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_reader.join();
            return Err(ImageError::Message(format!(
                "{name} timed out after {} seconds",
                ADAPTOR_TIMEOUT.as_secs()
            )));
        }
        thread::sleep(Duration::from_millis(10));
    };

    let (stdout, stdout_truncated) = stdout_reader
        .join()
        .map_err(|_| ImageError::Message(format!("{name} stdout reader panicked")))??;
    Ok(AdaptorOutput {
        status,
        stdout,
        stdout_truncated,
    })
}

fn read_capped<R: Read>(mut reader: R, cap: usize) -> std::io::Result<(Vec<u8>, bool)> {
    let mut out = Vec::new();
    let mut truncated = false;
    let mut buf = [0; 8192];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        let remaining = cap.saturating_sub(out.len());
        if remaining > 0 {
            let keep = remaining.min(n);
            out.extend_from_slice(&buf[..keep]);
        }
        if n > remaining {
            truncated = true;
        }
    }
    Ok((out, truncated))
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
        Self::create_with_stamp(&env::temp_dir(), stamp)
    }

    fn create_with_stamp(dir: &Path, stamp: u128) -> std::io::Result<Self> {
        let pid = std::process::id();
        for attempt in 0..TEMP_IMAGE_DIR_CREATE_ATTEMPTS {
            let path = dir.join(format!("fetch-image-{pid}-{stamp}-{attempt}"));
            match create_temp_image_dir(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(err) if err.kind() == ErrorKind::AlreadyExists => continue,
                Err(err) => return Err(err),
            }
        }

        Err(std::io::Error::new(
            ErrorKind::AlreadyExists,
            "unable to create unique temporary image directory",
        ))
    }
}

impl Drop for TempImageDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[cfg(unix)]
fn create_temp_image_dir(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    std::fs::DirBuilder::new().mode(0o700).create(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn create_temp_image_dir(path: &Path) -> std::io::Result<()> {
    std::fs::create_dir(path)
}

#[cfg(unix)]
fn write_temp_image_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    file.write_all(bytes)
}

#[cfg(not(unix))]
fn write_temp_image_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, bytes)
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

    #[test]
    fn decode_rejects_oversized_png_dimensions_before_full_allocation() {
        let bytes = png_with_dimensions(IMAGE_DIMENSION_LIMIT + 1, IMAGE_DIMENSION_LIMIT + 1);
        let err = decode_image_std(&bytes).unwrap_err();

        assert!(matches!(
            err,
            ImageError::Decode(::image::ImageError::Limits(_))
        ));
    }

    #[test]
    fn builtin_decode_mode_rejects_unsupported_bytes_without_external_adaptors() {
        let err = decode_image(b"not an image", DecodeMode::BuiltIn).unwrap_err();
        assert!(matches!(err, ImageError::Decode(_)));
    }

    #[cfg(unix)]
    #[test]
    fn external_decode_temp_paths_use_private_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempImageDir::create().unwrap();
        let dir_mode = std::fs::metadata(&dir.path).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700);

        let image_path = dir.path.join("fetch-temp-image");
        write_temp_image_file(&image_path, b"secret image bytes").unwrap();

        let file_mode = std::fs::metadata(&image_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(file_mode, 0o600);
        assert_eq!(std::fs::read(&image_path).unwrap(), b"secret image bytes");
    }

    #[test]
    fn external_decode_temp_dir_creation_retries_existing_candidates() {
        let root = tempfile::tempdir().unwrap();
        let stamp = 42;
        let stale = root
            .path()
            .join(format!("fetch-image-{}-{stamp}-0", std::process::id()));
        create_temp_image_dir(&stale).unwrap();

        let dir = TempImageDir::create_with_stamp(root.path(), stamp).unwrap();
        let expected = format!("fetch-image-{}-{stamp}-1", std::process::id());

        assert_eq!(
            dir.path.file_name().and_then(|name| name.to_str()),
            Some(expected.as_str())
        );
        assert!(stale.exists());
    }

    #[test]
    fn capped_reader_preserves_limit_and_drains_input() {
        let (out, truncated) = read_capped(Cursor::new(b"abcdef"), 4).unwrap();
        assert_eq!(out, b"abcd");
        assert!(truncated);

        let (out, truncated) = read_capped(Cursor::new(b"abc"), 4).unwrap();
        assert_eq!(out, b"abc");
        assert!(!truncated);
    }

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

    #[test]
    fn emulator_detection_protocol_mapping_matches_go() {
        assert_eq!(Emulator::Iterm2.protocol(), Protocol::Inline);
        assert_eq!(Emulator::WezTerm.protocol(), Protocol::Inline);
        assert_eq!(Emulator::Kitty.protocol(), Protocol::Kitty);
        assert_eq!(Emulator::Ghostty.protocol(), Protocol::Kitty);
        assert_eq!(Emulator::Apple.protocol(), Protocol::Block);
    }

    fn png_with_dimensions(width: u32, height: u32) -> Vec<u8> {
        let mut bytes = Vec::from(&[137, 80, 78, 71, 13, 10, 26, 10]);
        let mut ihdr = Vec::new();
        ihdr.extend_from_slice(&width.to_be_bytes());
        ihdr.extend_from_slice(&height.to_be_bytes());
        ihdr.extend_from_slice(&[8, 6, 0, 0, 0]);
        append_png_chunk(&mut bytes, b"IHDR", &ihdr);
        append_png_chunk(&mut bytes, b"IEND", &[]);
        bytes
    }

    fn append_png_chunk(bytes: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
        bytes.extend_from_slice(&u32::try_from(data.len()).unwrap().to_be_bytes());
        bytes.extend_from_slice(kind);
        bytes.extend_from_slice(data);
        bytes.extend_from_slice(&png_crc32(kind, data).to_be_bytes());
    }

    fn png_crc32(kind: &[u8; 4], data: &[u8]) -> u32 {
        let mut crc = 0xffff_ffff_u32;
        for byte in kind.iter().chain(data) {
            crc ^= u32::from(*byte);
            for _ in 0..8 {
                crc = if crc & 1 == 0 {
                    crc >> 1
                } else {
                    (crc >> 1) ^ 0xedb8_8320
                };
            }
        }
        !crc
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
