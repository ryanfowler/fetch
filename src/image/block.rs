// Much of the code in this file was inspired by the code from the viuer crate
// with the following license:

// MIT License

// Copyright (c) 2022 Atanas Yankov

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use std::{env, io};

use ansi_colours::ansi256_from_rgb;
use crossterm::{cursor::MoveRight, execute};
use image::{DynamicImage, Rgba};
use termcolor::{BufferedStandardStream, Color, ColorSpec, WriteColor};

use super::Image;

static UPPER_HALF_BLOCK: &str = "\u{2580}";
static LOWER_HALF_BLOCK: &str = "\u{2584}";

pub(crate) fn write_to_stdout(img: Image) -> io::Result<()> {
    let mut stdout = BufferedStandardStream::stdout(termcolor::ColorChoice::Always);
    write_blocks(&mut stdout, img.dynamic_image())
}

fn write_blocks(stdout: &mut impl WriteColor, img: &DynamicImage) -> io::Result<()> {
    let use_truecolor = supports_truecolor();

    // Resize image to be the exact number of pixels as rows/columns.
    let (cols, rows) = super::image_block_output_dimensions(img)?;
    let img = img.thumbnail(cols, 2 * rows);

    let mut row_buf = vec![ColorSpec::new(); cols as usize];
    let buf = img.to_rgba8();

    for (index, img_row) in buf.enumerate_rows() {
        let is_top_row = index % 2 == 0;
        let is_last_row = index == 2 * rows - 1;

        for pixel in img_row {
            let color = if pixel.2[3] == 0 {
                // Pixel is transparent.
                None
            } else {
                Some(get_color_from_pixel(pixel, use_truecolor))
            };

            // Even rows modify the background and odd rows the foreground.
            let colorspec = &mut row_buf[pixel.0 as usize];
            if is_top_row {
                colorspec.set_bg(color);
                if is_last_row {
                    write_colored_character(stdout, colorspec, true)?;
                }
            } else {
                colorspec.set_fg(color);
                write_colored_character(stdout, colorspec, false)?;
            }
        }

        if !is_top_row && !is_last_row {
            stdout.reset()?;
            write!(stdout, "\r\n")?;
        }
    }

    stdout.reset()?;
    writeln!(stdout)?;
    stdout.flush()
}

fn supports_truecolor() -> bool {
    env::var("COLORTERM").is_ok_and(|v| v.contains("truecolor") || v.contains("24bit"))
}

fn get_color_from_pixel(pixel: (u32, u32, &Rgba<u8>), truecolor: bool) -> Color {
    let (_x, _y, data) = pixel;
    let rgb = (data[0], data[1], data[2]);
    if truecolor {
        Color::Rgb(rgb.0, rgb.1, rgb.2)
    } else {
        Color::Ansi256(ansi256_from_rgb(rgb))
    }
}

fn write_colored_character(
    stdout: &mut impl WriteColor,
    c: &ColorSpec,
    is_last_row: bool,
) -> io::Result<()> {
    let out_color;
    let out_char;
    let mut new_color;

    // On the last row use upper blocks and leave the bottom half empty (transparent)
    if is_last_row {
        new_color = ColorSpec::new();
        if let Some(bg) = c.bg() {
            new_color.set_fg(Some(*bg));
            out_char = UPPER_HALF_BLOCK;
        } else {
            execute!(stdout, MoveRight(1))?;
            return Ok(());
        }
        out_color = &new_color;
    } else {
        match (c.fg(), c.bg()) {
            (None, None) => {
                // Completely transparent.
                execute!(stdout, MoveRight(1))?;
                return Ok(());
            }
            (Some(bottom), None) => {
                // Only top transparent.
                new_color = ColorSpec::new();
                new_color.set_fg(Some(*bottom));
                out_color = &new_color;
                out_char = LOWER_HALF_BLOCK;
            }
            (None, Some(top)) => {
                // Only bottom transparent.
                new_color = ColorSpec::new();
                new_color.set_fg(Some(*top));
                out_color = &new_color;
                out_char = UPPER_HALF_BLOCK;
            }
            (Some(_top), Some(_bottom)) => {
                // Both parts have a color.
                out_color = c;
                out_char = LOWER_HALF_BLOCK;
            }
        }
    }
    stdout.set_color(out_color)?;
    write!(stdout, "{out_char}")
}
