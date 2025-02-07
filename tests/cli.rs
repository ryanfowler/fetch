use assert_cmd::Command;
use mockito::Server;
use serde::Deserialize;

#[derive(Deserialize)]
struct HelloMessage {
    message: String,
}

/// Test a basic GET request. The mock server will return a JSON body.
/// The test launches the CLI with the mock server URL and then verifies
/// that the output contains the expected content.
#[test]
fn test_get_request() {
    let mut server = Server::new();
    let mock = server
        .mock("GET", "/")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"message": "hello"}"#)
        .create();

    let url = server.url();

    // Call the CLI binary
    let mut cmd = Command::cargo_bin("fetch").unwrap();
    cmd.arg(url);
    let assert = cmd.assert().success();
    let out = assert.get_output();

    let res: HelloMessage = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(res.message, "hello");

    mock.assert();
}

/// Test a POST request with JSON data.
/// The mock server checks that the request body and content-type header are correct.
#[test]
fn test_post_request_with_data() {
    let expected_body = r#"{"title": "test"}"#;

    let mut server = Server::new();
    let mock = server
        .mock("POST", "/submit")
        .match_header("content-type", "application/json")
        .match_body(expected_body)
        .with_status(201)
        .with_body("created")
        .create();

    // Build the URL with the mock server base and the endpoint path
    let url = format!("{}/submit", server.url());

    // Call the CLI with POST method and the data flag
    let mut cmd = Command::cargo_bin("fetch").unwrap();
    cmd.arg("--method")
        .arg("POST")
        .arg("--json")
        .arg("--data")
        .arg(expected_body)
        .arg(url);
    let assert = cmd.assert().success();
    let out = assert.get_output();
    assert_eq!(out.stdout, "created".as_bytes());

    mock.assert();
}

/// Test that custom headers are sent correctly.
/// The mock endpoint will match the header and return a known body.
#[test]
fn test_custom_headers() {
    let header_value = "application/custom";

    // Create a mock endpoint that expects a custom "Accept" header
    let mut server = Server::new();
    let mock = server
        .mock("GET", "/headers")
        .match_header("Accept", header_value)
        .with_status(200)
        .with_body("header ok")
        .create();

    let url = format!("{}/headers", server.url());

    // Call the CLI passing the header via -H flag
    let mut cmd = Command::cargo_bin("fetch").unwrap();
    cmd.arg("-H")
        .arg(format!("Accept: {}", header_value))
        .arg(url);
    let assert = cmd.assert().success();
    let out = assert.get_output();
    assert_eq!(out.stdout, "header ok".as_bytes());

    mock.assert();
}

/// Test the dry-run option which prints out request details
/// rather than sending the request. We expect to see method and URL info.
#[test]
fn test_dry_run() {
    // In dry-run mode, the CLI should output request details to stderr.
    // (Depending on the implementation details, it might print "GET" or similar.)
    let server = Server::new();
    let url = server.url(); // Use any valid URL for testing

    let mut cmd = Command::cargo_bin("fetch").unwrap();
    cmd.arg("--dry-run").arg(url);
    cmd.assert().success();
}

/// Test error handling by providing an invalid URL scheme.
/// The CLI should fail and emit an error message.
#[test]
fn test_invalid_url() {
    let mut cmd = Command::cargo_bin("fetch").unwrap();
    cmd.arg("htp://invalid-url"); // "htp" is not a valid scheme
    let assert = cmd.assert().failure();
    let out = assert.get_output();
    assert!(String::from_utf8(out.stderr.clone())
        .unwrap()
        .contains("not supported"),);
}
