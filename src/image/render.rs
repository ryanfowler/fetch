use std::fmt;

use ::image::codecs::png::PngEncoder;
use ::image::imageops::FilterType;
use ::image::{ColorType, DynamicImage, GenericImageView, ImageEncoder, Rgba};
use base64::Engine;

use super::ImageError;

pub(crate) fn write_blocks(
    img: &DynamicImage,
    term_width: u32,
    term_height: u32,
    true_color: bool,
) -> Vec<u8> {
    let (cols, rows) = image_block_output_dimensions(img, term_width, term_height);
    let target_width = cols.max(1);
    let target_height = rows.saturating_mul(2).max(1);
    let dst = resize_image(img, target_width, target_height);

    let mut out = String::new();
    let mut ansi = AnsiState::default();
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
            write_block(&mut out, &mut ansi, top, bottom, true_color);
        }
        ansi.reset(&mut out);
        out.push('\n');
    }
    out.into_bytes()
}

fn image_block_output_dimensions(
    img: &DynamicImage,
    term_width: u32,
    term_height: u32,
) -> (u32, u32) {
    let cols = term_width.max(1);
    let rows = scaled_u32(term_height, 8, 5).max(1);
    let (width, height) = img.dimensions();
    if width == 0 || height == 0 {
        return (1, 1);
    }
    if width <= cols && height <= rows {
        return (width.max(1), (height / 2 + height % 2).max(1));
    }
    if product_u64(cols, height) <= product_u64(width, rows) {
        let height_pixels = product_u64(height, cols) / u64::from(width);
        return (cols, u64_to_u32(height_pixels / 2).max(1));
    }
    let scaled_width = product_u64(width, rows) / u64::from(height);
    (u64_to_u32(scaled_width).max(1), (rows / 2).max(1))
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
    ansi: &mut AnsiState,
    top: Option<RgbColor>,
    bottom: Option<RgbColor>,
    true_color: bool,
) {
    match (top, bottom) {
        (None, None) => {
            ansi.clear_fg(out);
            ansi.clear_bg(out);
            out.push(' ');
        }
        (Some(top), None) => {
            ansi.clear_bg(out);
            ansi.set_fg(out, top, true_color);
            out.push('▀');
        }
        (None, Some(bottom)) => {
            ansi.clear_bg(out);
            ansi.set_fg(out, bottom, true_color);
            out.push('▄');
        }
        (Some(top), Some(bottom)) => {
            ansi.set_bg(out, top, true_color);
            ansi.set_fg(out, bottom, true_color);
            out.push('▄');
        }
    }
}

#[derive(Default)]
struct AnsiState {
    fg: Option<RgbColor>,
    bg: Option<RgbColor>,
}

impl AnsiState {
    fn set_fg(&mut self, out: &mut String, color: RgbColor, true_color: bool) {
        if self.fg == Some(color) {
            return;
        }
        ansi_fg(out, color, true_color);
        self.fg = Some(color);
    }

    fn set_bg(&mut self, out: &mut String, color: RgbColor, true_color: bool) {
        if self.bg == Some(color) {
            return;
        }
        ansi_bg(out, color, true_color);
        self.bg = Some(color);
    }

    fn clear_fg(&mut self, out: &mut String) {
        if self.fg.take().is_some() {
            out.push_str("\x1b[39m");
        }
    }

    fn clear_bg(&mut self, out: &mut String) {
        if self.bg.take().is_some() {
            out.push_str("\x1b[49m");
        }
    }

    fn reset(&mut self, out: &mut String) {
        if self.fg.is_some() || self.bg.is_some() {
            out.push_str("\x1b[0m");
            self.fg = None;
            self.bg = None;
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

pub(crate) fn write_inline(
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

pub(crate) fn write_kitty(
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

fn scaled_u32(value: u32, numerator: u64, denominator: u64) -> u32 {
    let scaled = u64::from(value).saturating_mul(numerator) / denominator.max(1);
    u64_to_u32(scaled)
}

fn product_u64(left: u32, right: u32) -> u64 {
    u64::from(left) * u64::from(right)
}

fn u64_to_u32(value: u64) -> u32 {
    value.min(u64::from(u32::MAX)) as u32
}

fn resize_for_term(img: &DynamicImage, term_width_px: u32, term_height_px: u32) -> DynamicImage {
    if term_width_px == 0 || term_height_px == 0 {
        return img.clone();
    }

    let term_height_px = scaled_u32(term_height_px, 4, 5).max(1);
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

#[cfg(test)]
mod tests {
    use super::*;
    use ::image::{DynamicImage, Rgba, RgbaImage};

    fn img_1x2() -> DynamicImage {
        let mut img = RgbaImage::new(1, 2);
        img.put_pixel(0, 0, Rgba([255, 0, 0, 255]));
        img.put_pixel(0, 1, Rgba([0, 0, 255, 255]));
        DynamicImage::ImageRgba8(img)
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
        assert_eq!(out, "\x1b[48;2;255;0;0m\x1b[38;2;0;0;255m▄\x1b[0m\n");
    }

    #[test]
    fn image_dimension_math_handles_extreme_terminal_sizes() {
        let img = DynamicImage::ImageRgba8(RgbaImage::new(8192, 8192));

        assert_eq!(image_block_output_dimensions(&img, u32::MAX, 1), (1, 1));
        assert_eq!(
            image_block_output_dimensions(&img, u32::MAX, u32::MAX),
            (8192, 4096)
        );

        let resized = resize_for_term(&img, u32::MAX, u32::MAX);
        assert_eq!(resized.dimensions(), (8192, 8192));
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
}
