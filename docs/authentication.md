# Authentication

`fetch` supports multiple authentication methods for accessing protected resources.

## HTTP Basic Authentication

Basic Authentication sends credentials as a base64-encoded `Authorization` header.

### Command Line

```sh
fetch --basic username:password example.com
```

### How It Works

The `--basic` flag sets the `Authorization` header:

```
Authorization: Basic base64(username:password)
```

## Bearer Token Authentication

Bearer tokens are commonly used with OAuth 2.0 and JWT-based authentication.

### Command Line

```sh
fetch --bearer mytoken123 example.com
```

### How It Works

The `--bearer` flag sets the `Authorization` header:

```
Authorization: Bearer mytoken123
```

### Using Environment Variables

For security, avoid putting tokens directly in commands:

```sh
fetch --bearer "$API_TOKEN" example.com
```

Or read from a file:

```sh
fetch -H "Authorization: Bearer $(cat ~/.api-token)" example.com
```

## AWS Signature V4

Sign requests for AWS services using [AWS Signature V4](https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-authenticating-requests.html).

### Prerequisites

Set the required environment variables:

```sh
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
```

### Command Line

```sh
fetch --aws-sigv4 REGION/SERVICE url
```

### Examples

```sh
# S3 request
fetch --aws-sigv4 us-east-1/s3 https://my-bucket.s3.amazonaws.com/key

# API Gateway
fetch --aws-sigv4 us-west-2/execute-api https://abc123.execute-api.us-west-2.amazonaws.com/prod/resource

# Lambda function URL
fetch --aws-sigv4 eu-west-1/lambda https://xyz.lambda-url.eu-west-1.on.aws/
```

### How It Works

AWS SigV4 signs the request by:

1. Creating a canonical request from the HTTP method, path, query string, headers, and body
2. Generating a signing key from your secret key, date, region, and service
3. Computing an HMAC-SHA256 signature
4. Adding the signature to the `Authorization` header

## Mutual TLS (mTLS)

mTLS provides two-way authentication where both client and server present certificates.

### Basic Usage

```sh
fetch --cert client.crt --key client.key example.com
```

### Combined Certificate and Key

If your PEM file contains both the certificate and private key:

```sh
fetch --cert client.pem example.com
```

### With Custom CA Certificate

When the server uses a private CA:

```sh
fetch --cert client.crt --key client.key --ca-cert ca.crt example.com
```

### Configuration File

```ini
# Global mTLS settings
cert = /path/to/client.crt
key = /path/to/client.key

# Host-specific mTLS
[api.secure.example.com]
cert = /path/to/api-client.crt
key = /path/to/api-client.key
ca-cert = /path/to/api-ca.crt
```

### Certificate Formats

- Certificates and keys must be in PEM format
- Encrypted private keys are not supported
- Combined PEM files should have the certificate before the key

### Example: Self-Signed Certificates

Generate test certificates:

```sh
# Generate CA
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 365 -key ca.key -out ca.crt -subj "/CN=Test CA"

# Generate client certificate
openssl genrsa -out client.key 4096
openssl req -new -key client.key -out client.csr -subj "/CN=client"
openssl x509 -req -days 365 -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt
```

Use with fetch:

```sh
fetch --cert client.crt --key client.key --ca-cert ca.crt https://mtls.example.com
```

## Custom Headers

For authentication methods not directly supported, use custom headers:

```sh
# API Key in header
fetch -H "X-API-Key: your-api-key" example.com

# Custom token format
fetch -H "X-Auth-Token: custom-token" example.com

# Multiple auth headers
fetch -H "X-API-Key: key" -H "X-Signature: sig" example.com
```

### Configuration File

```ini
[api.example.com]
header = X-API-Key: your-api-key
header = X-Client-ID: client123
```

## Authentication Precedence

Authentication options are mutually exclusive. You cannot combine:

- `--basic`
- `--bearer`
- `--aws-sigv4`

If you need multiple authentication headers, use `-H` for additional headers.

## Security Considerations

1. **Avoid embedding secrets in scripts** - Use environment variables or secure vaults
2. **Protect configuration files** - Set appropriate file permissions (`chmod 600`)
3. **Use HTTPS** - Never send credentials over unencrypted HTTP
4. **Rotate credentials regularly** - Especially API keys and tokens

### Secure Credential Handling

```sh
# Using environment variables
export API_TOKEN="$(vault read -field=token secret/api)"
fetch --bearer "$API_TOKEN" example.com

# Using password manager
fetch --basic "$(pass show api/credentials)" example.com

# Reading from secure file
fetch --bearer "$(cat /run/secrets/api-token)" example.com
```

## Troubleshooting

### 401 Unauthorized

- Verify credentials are correct
- Check if the authentication method matches what the server expects
- Ensure tokens haven't expired

### 403 Forbidden

- Authentication succeeded but authorization failed
- Check if your credentials have the required permissions

### Certificate Errors with mTLS

- Verify certificate and key match: `openssl x509 -noout -modulus -in cert.crt | openssl md5` should match `openssl rsa -noout -modulus -in key.key | openssl md5`
- Check certificate expiration: `openssl x509 -noout -dates -in cert.crt`
- Ensure the CA certificate is correct for the server

### AWS SigV4 Errors

- Verify `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` are set
- Check the region and service name are correct
- Ensure your credentials have the required IAM permissions
- Verify system clock is accurate (signatures are time-sensitive)

## See Also

- [CLI Reference](cli-reference.md) - All authentication flags
- [Configuration](configuration.md) - Setting up authentication in config files
- [Troubleshooting](troubleshooting.md) - Common issues and solutions
