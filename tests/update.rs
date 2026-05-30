mod support;

use support::*;

#[cfg(not(windows))]
#[test]
fn self_update_go_harness_cases() {
    let dir = TempDir::new().unwrap();
    let update_bin = dir.path().join("fetch");
    install_update_launcher(&update_bin);
    let auto_update_bin = dir.path().join("fetch-auto");
    install_update_launcher(&auto_update_bin);

    let current_version = fetch_version();
    let latest_version = Arc::new(Mutex::new(current_version.clone()));
    let update_requests = Arc::new(AtomicUsize::new(0));
    let server_url = Arc::new(Mutex::new(String::new()));
    let latest_for_handler = Arc::clone(&latest_version);
    let requests_for_handler = Arc::clone(&update_requests);
    let server_url_for_handler = Arc::clone(&server_url);
    let server = TestServer::start(move |req| {
        requests_for_handler.fetch_add(1, Ordering::SeqCst);
        let version = latest_for_handler.lock().unwrap().clone();
        let artifact_name = update_artifact_name(&version);
        if req.path == "/artifact" {
            return TestResponse::ok(make_update_artifact(&version));
        }
        if req.path == "/artifact.sha256" {
            let artifact = make_update_artifact(&version);
            return TestResponse::ok(update_artifact_checksum_line(&artifact_name, &artifact));
        }
        let base = server_url_for_handler.lock().unwrap().clone();
        let body = format!(
            r#"{{"tag_name":"{version}","assets":[{{"name":"{artifact_name}","browser_download_url":"{base}/artifact"}},{{"name":"{artifact_name}.sha256","browser_download_url":"{base}/artifact.sha256"}}]}}"#
        );
        TestResponse::ok(body).header("Content-Type", "application/json")
    });
    *server_url.lock().unwrap() = server.url.clone();

    let env = vec![("FETCH_INTERNAL_UPDATE_URL".to_string(), server.url.clone())];
    let opts = |bin: &Path, env: Vec<(String, String)>| FetchOpts {
        bin: Some(bin.to_path_buf()),
        env,
        ..Default::default()
    };

    let original_modified = fs::metadata(&update_bin).unwrap().modified().unwrap();
    let res = run_fetch_opts(opts(&update_bin, env.clone()), &[&server.url, "--update"]);
    assert_exit(&res, 0);
    assert!(res.stderr.contains("Already using the latest version"));
    assert_eq!(
        fs::read_dir(dir.path()).unwrap().count(),
        2,
        "unexpected update temp files"
    );
    assert_eq!(
        fs::metadata(&update_bin).unwrap().modified().unwrap(),
        original_modified
    );

    *latest_version.lock().unwrap() = "v999.0.0-test".to_string();
    let dry_same_modified = fs::metadata(&update_bin).unwrap().modified().unwrap();
    *latest_version.lock().unwrap() = current_version;
    let res = run_fetch_opts(
        opts(&update_bin, env.clone()),
        &[&server.url, "--update", "--dry-run"],
    );
    assert_exit(&res, 0);
    assert!(res.stderr.contains("Already using the latest version"));
    assert_eq!(
        fs::metadata(&update_bin).unwrap().modified().unwrap(),
        dry_same_modified
    );

    *latest_version.lock().unwrap() = "v999.0.0-test".to_string();
    let dry_new_modified = fs::metadata(&update_bin).unwrap().modified().unwrap();
    let res = run_fetch_opts(
        opts(&update_bin, env.clone()),
        &[&server.url, "--update", "--dry-run"],
    );
    assert_exit(&res, 0);
    assert!(res.stderr.contains("Update available"));
    assert!(res.stderr.contains("v999.0.0-test"));
    assert!(!res.stderr.contains("Updated fetch:"));
    assert!(!res.stderr.contains("Downloading"));
    assert_eq!(
        fs::metadata(&update_bin).unwrap().modified().unwrap(),
        dry_new_modified
    );

    let before_metadata_requests = update_requests.load(Ordering::SeqCst);
    let before_metadata_modified = fs::metadata(&update_bin).unwrap().modified().unwrap();
    let mut metadata_env = env.clone();
    metadata_env.push((
        "FETCH_INTERNAL_SYNC_AUTO_UPDATE".to_string(),
        "1".to_string(),
    ));
    let res = run_fetch_opts(
        opts(&update_bin, metadata_env),
        &["--version", "--auto-update", "0s"],
    );
    assert_exit(&res, 0);
    assert_eq!(
        update_requests.load(Ordering::SeqCst),
        before_metadata_requests,
        "metadata command started an auto-update request"
    );
    assert_eq!(
        fs::metadata(&update_bin).unwrap().modified().unwrap(),
        before_metadata_modified
    );

    let res = run_fetch_opts(opts(&update_bin, env.clone()), &[&server.url, "--update"]);
    assert_exit(&res, 0);
    assert!(res.stderr.contains("Updated fetch:"));
    assert!(res.stderr.contains("Changelog:"));
    assert_eq!(
        fs::read_dir(dir.path()).unwrap().count(),
        2,
        "unexpected update temp files"
    );
    assert_ne!(
        fs::metadata(&update_bin).unwrap().modified().unwrap(),
        original_modified
    );

    let res = run_fetch_opts(opts(&update_bin, env.clone()), &["--version"]);
    assert_exit(&res, 0);
    assert!(res.stdout.contains("fetch v999.0.0-test"));

    *latest_version.lock().unwrap() = "v1000.0.0-test".to_string();
    let auto_update_modified = fs::metadata(&auto_update_bin).unwrap().modified().unwrap();
    let mut sync_auto_update_env = env.clone();
    sync_auto_update_env.push((
        "FETCH_INTERNAL_SYNC_AUTO_UPDATE".to_string(),
        "1".to_string(),
    ));
    let res = run_fetch_opts(
        opts(&auto_update_bin, sync_auto_update_env),
        &[&server.url, "--auto-update", "0s"],
    );
    assert_exit(&res, 0);
    assert_ne!(
        fs::metadata(&auto_update_bin).unwrap().modified().unwrap(),
        auto_update_modified
    );

    let res = run_fetch_opts(opts(&auto_update_bin, env), &["--version"]);
    assert_exit(&res, 0);
    assert!(res.stdout.contains("fetch v1000.0.0-test"));
}
