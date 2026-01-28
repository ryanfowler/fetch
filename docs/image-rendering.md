# Image Rendering

`fetch` can render images directly in your terminal when fetching image URLs.

## Image Control

### `--image OPTION`

Control how images are rendered:

| Value    | Description                                                |
| -------- | ---------------------------------------------------------- |
| `auto`   | Try optimal protocol, fallback to external tools (default) |
| `native` | Use only built-in decoders                                 |
| `off`    | Disable image rendering                                    |

```sh
fetch --image native example.com/photo.jpg
fetch --image off example.com/image.png
```

## Supported Image Formats

### Built-in Decoders (Native)

These formats are decoded without external tools:

- **JPEG** - `.jpg`, `.jpeg`
- **PNG** - `.png`
- **TIFF** - `.tiff`, `.tif`
- **WebP** - `.webp`

### With External Adapters

When `--image auto` (default), these additional formats are supported if you have the required tools installed:

- **AVIF** - `.avif`
- **HEIF/HEIC** - `.heif`, `.heic`
- **GIF** - `.gif` (static frame)
- **BMP** - `.bmp`
- **And many more...**

## Terminal Protocols

`fetch` automatically detects your terminal and uses the best available image protocol.

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

When native decoders can't handle an image format, `fetch` tries external tools in this order:

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

# Use only native decoders
image = native

# Auto-detect (default)
image = auto
```

## Image Sizing

Images are automatically resized to fit within 80% of the terminal height while maintaining aspect ratio. This ensures images don't overwhelm the terminal display.

## Examples

### View an Image

```sh
fetch example.com/photo.jpg
```

### Download Instead of Display

```sh
fetch -o photo.jpg example.com/photo.jpg
```

### Force Native Decoding

```sh
fetch --image native example.com/image.png
```

### Disable Image Rendering

```sh
fetch --image off example.com/image.jpg
```

## Troubleshooting

### Image Not Displaying

1. **Check terminal support**: Not all terminals support inline images
2. **Verify format**: Use `--image native` to test if it's a format issue
3. **Install adapters**: Install VIPS, ImageMagick, or FFmpeg for more formats
4. **Check terminal size**: Very small terminals may not render properly

### Poor Quality

1. **Use a native protocol terminal**: Kitty, Ghostty, or iTerm2 provide best quality
2. **Check image dimensions**: Very large images are resized
3. **Block character fallback**: Quality is limited with Unicode blocks

### Colors Look Wrong

1. **Terminal color support**: Ensure your terminal supports 24-bit color
2. **tmux/screen**: May reduce color depth
3. **Try native decoding**: `--image native`

### Image Dimensions Too Large

`fetch` limits images to 8192x8192 pixels maximum to prevent memory issues. Larger images will fail to decode with a "dimensions are too large" error.

## Limitations

- **Animated GIFs**: Only the first frame is displayed
- **Maximum size**: 8192x8192 pixels
- **Memory limit**: Images are loaded into memory for processing
- **Terminal multiplexers**: tmux and screen may interfere with image protocols

## See Also

- [CLI Reference](cli-reference.md) - Image option details
- [Output Formatting](output-formatting.md) - Other content type handling
- [Configuration](configuration.md) - Default image settings
