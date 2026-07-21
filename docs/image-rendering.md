# Image Rendering

`fetch` renders images directly in the terminal.

## Image Control

### `--image OPTION`

Control how images are rendered:

| Value      | Description                                                    |
| ---------- | -------------------------------------------------------------- |
| `auto`     | Try optimal terminal protocol with built-in decoders (default) |
| `external` | Allow external adapters for additional formats                 |
| `off`      | Disable image rendering                                        |

```sh
fetch --image external example.com/photo.avif
fetch --image off example.com/image.png
```

## Supported Image Formats

### Built-in Decoders

These formats are decoded without external tools:

- **JPEG** - `.jpg`, `.jpeg`
- **PNG** - `.png`
- **TIFF** - `.tiff`, `.tif`
- **WebP** - `.webp`

### With External Adapters

If you set `--image external`, `fetch` supports these additional formats when
the necessary tools are installed:

- **AVIF** - `.avif`
- **HEIF/HEIC** - `.heif`, `.heic`
- **GIF** - `.gif` (static frame)
- **BMP** - `.bmp`

The installed adapters can support other formats.

## Terminal Protocols

`fetch` detects the terminal and selects the first applicable image protocol.

### Kitty Graphics Protocol

**Supported terminals**: Kitty, Ghostty, Konsole

The highest quality protocol with full color support and efficient transmission.

### iTerm2 Inline Images

**Supported terminals**: iTerm2, WezTerm, Hyper, Mintty

Base64-encoded PNG images displayed inline.

### Unicode Block Characters

**Supported terminals**: All terminals

Fallback rendering using Unicode block characters (▀▄█). Works everywhere but with reduced resolution.

## Terminal Detection

`fetch` detects your terminal emulator through environment variables:

| Terminal         | Detection Method                               |
| ---------------- | ---------------------------------------------- |
| Kitty            | `KITTY_PID` or `TERM=xterm-kitty`              |
| Ghostty          | `GHOSTTY_BIN_DIR` or `TERM=xterm-ghostty`      |
| iTerm2           | `ITERM_SESSION_ID` or `TERM_PROGRAM=iTerm.app` |
| WezTerm          | `WEZTERM_EXECUTABLE` or `TERM_PROGRAM=WezTerm` |
| Konsole          | `KONSOLE_VERSION`                              |
| Hyper            | `TERM_PROGRAM=Hyper`                           |
| Mintty           | `TERM_PROGRAM=mintty`                          |
| VS Code          | `TERM_PROGRAM=vscode` or `VSCODE_INJECTION`    |
| Windows Terminal | `WT_SESSION`                                   |
| Apple Terminal   | `TERM_PROGRAM=Apple_Terminal`                  |
| Alacritty        | `TERM=alacritty`                               |
| Zellij           | `ZELLIJ`                                       |
| tmux             | `TERM_PROGRAM=tmux`                            |

## External Adapters

If the built-in decoders do not support an image format, set `--image
external`. `fetch` tries these external tools in the specified order:

### 1. VIPS (`vips`)

Fast image processing library.

```sh
# Install on macOS
brew install vips

# Install on Ubuntu/Debian
apt install libvips-tools
```

### 2. ImageMagick (`magick`)

Comprehensive image manipulation tool.

```sh
# Install on macOS
brew install imagemagick

# Install on Ubuntu/Debian
apt install imagemagick
```

### 3. FFmpeg (`ffmpeg`)

Multimedia framework with image support.

```sh
# Install on macOS
brew install ffmpeg

# Install on Ubuntu/Debian
apt install ffmpeg
```

## Configuration

Set image rendering preferences in your [configuration file](configuration.md):

```ini
# Disable image rendering
image = off

# Auto-detect terminal protocol with built-in decoders (default)
image = auto

# Opt in to external adapters
image = external
```

## Image Sizing

`fetch` resizes images to a maximum of 80% of the terminal height. It keeps the
image aspect ratio.

## Examples

### View an Image

```sh
fetch example.com/photo.jpg
```

### Download Instead of Display

```sh
fetch -o photo.jpg example.com/photo.jpg
```

### Disable Image Rendering

```sh
fetch --image off example.com/image.jpg
```

## Troubleshooting

### Image Not Displaying

1. **Check terminal support**: Not all terminals support inline images
2. **Verify format**: Built-in decoders handle JPEG, PNG, TIFF, and WebP by default
3. **Install adapters**: Install VIPS, ImageMagick, or FFmpeg and use `--image external` for more formats
4. **Check the terminal size**: Increase the size if the image does not render.

### Poor Quality

1. **Use a native-protocol terminal**: Kitty, Ghostty, and iTerm2 give the
   highest quality.
2. **Check image dimensions**: `fetch` resizes large images.
3. **Block character fallback**: Quality is limited with Unicode blocks

### Colors Look Wrong

1. **Terminal color support**: Make sure that the terminal supports 24-bit
   color.
2. **tmux or screen**: Test without the terminal multiplexer because it can
   reduce the color depth.
3. **Try default decoding**: `--image auto`

### Image Dimensions Too Large

`fetch` limits images to 8192 x 8192 pixels to prevent memory problems. It
reports a `dimensions are too large` error for larger images.

## Limitations

- **Animated GIFs**: `fetch` displays only the first frame.
- **Maximum size**: The limit is 8192 x 8192 pixels.
- **Memory limit**: `fetch` loads images into memory for processing.
- **Terminal multiplexers**: tmux and screen can interfere with image protocols.

## See Also

- [CLI Reference](cli-reference.md) - Image option details
- [Output Formatting](output-formatting.md) - Other content type handling
- [Configuration](configuration.md) - Default image settings
