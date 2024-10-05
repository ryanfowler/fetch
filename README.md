# fetch

`fetch` is a modern HTTP(S) client for the command line.

It's features include:
- auto formatted and colored output for supported types (e.g. json, xml, etc.)
- render images directly in your terminal
- easily sign requests with [AWS Signature V4](https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-authenticating-requests.html)
- optionally use an editor to define the request body
- automatic response body decompression for gzip, deflate, brotli, and zstd
- and more!

## Install

#### Download binary

TBD

#### Install through `cargo`

Requires having the following dependencies installed:
- TODO

```sh
cargo install --force --locked fetch-cli
```

## Usage

#### Basic usage

```sh
# Make a simple GET request
# fetch will default to using HTTPS if no scheme is specified.
fetch example.com

# Make a PUT request with inline body
fetch -m PUT --data 'request body' example.com

# Make a PUT request with inline JSON body
# The --json flag will set the content-type header to 'application/json'
fetch -m PUT --json --data '{"key":"val"}' example.com

# Send a JSON request body from a local file
fetch -m PUT --json --data '@local/file.json' example.com

# Use an editor to define the JSON request body
fetch -m PUT --json --edit example.com
```

#### Verbosity

```sh
# By default, fetch will write the HTTP version and status to stderr.
fetch example.com

# HTTP/1.1 200 OK
#
# [response data]

# Providing the verbose flag a single time will also output the response headers
fetch -v example.com

# HTTP/1.1 200 OK
# date: Sat, 05 Oct 2024 04:42:51 GMT
# content-type: application/json; charset=utf-8
# content-length: 456
#
# [response data]

# Providing the verbose flag twice will also output the request headers
fetch -vv example.com

# GET / HTTP/1.1
# host: example.com
# accept: */*
# accept-encoding: gzip, deflate, br, zstd
# user-agent: fetch/0.1.0
#
# HTTP/1.1 200 OK
# date: Sat, 05 Oct 2024 04:42:51 GMT
# content-type: application/json; charset=utf-8
# content-length: 456
#
# [response data]

# If you don't want any metadata written to stderr, use the silent flag
fetch -s example.com

# [response data]
```

#### Headers

```sh
# Set a custom request header for the request in the 'key:value' format
fetch -H x-custom-header:value1 example.com

# Set multiple request headers
fetch -H x-custom-header:value1 -H x-another-header:value2 example.com
```

#### Query parameters

```sh
# Append a query parameter to the request in the 'key=value' format
fetch -q key=value example.com

# Parameters will be appended to any exist query parameters on the request
fetch -q key1=value1 -q key2=value2 "example.com?existing=param"
```

#### Send a request with a form body

```sh
# Send a POST request with a form body.
# Sets the content-type to 'application/x-www-form-urlencoded'
fetch -m POST -f key1=value1 -f key2=value2 example.com
```

#### AWS signature v4

```sh
# Sign a request with aws signature v4.
# This will set the x-amx-date, authorization, and optionally the x-amx-content-sha256 headers
export AWS_ACCESS_KEY_ID=AWSACCESSKEYID
export AWS_SECRET_ACCESS_KEY=SEcrETAccESSkEY
fetch mybucket.example.com --aws-sigv4 us-east-1/s3
```

## Images

Images will be automatically rendered in your terminal.

High quality images will be rendered in the following terminals:
- ghostty
- kitty
- wezterm
- iterm2
- mintty
- konsole

A low quality block-based image will be rendered in all other terminal emulators.

Supported image types are:
- jpeg
- png
- webp
- avif
- tiff
