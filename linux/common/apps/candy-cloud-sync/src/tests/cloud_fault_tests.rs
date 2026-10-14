use super::*;
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::sync::{
    atomic::{AtomicBool, AtomicU8, Ordering},
    Arc, Mutex,
};
use std::thread;

struct CloudFixture {
    address: SocketAddr,
    mode: Arc<AtomicU8>,
    stop: Arc<AtomicBool>,
    requests: Arc<Mutex<Vec<String>>>,
    task: Option<thread::JoinHandle<()>>,
}

impl CloudFixture {
    fn start(root: &Path) -> Self {
        let config = root.join("tls.cnf");
        fs::write(&config, "[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n[dn]\nCN=localhost\n[ext]\nsubjectAltName=IP:127.0.0.1\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,digitalSignature,keyCertSign,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth\n").unwrap();
        let certificate = root.join("ca.pem");
        let key = root.join("key.pem");
        let output = ProcessCommand::new("openssl")
            .args([
                "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-config",
            ])
            .arg(config)
            .arg("-keyout")
            .arg(&key)
            .arg("-out")
            .arg(&certificate)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let leaf_config = root.join("leaf.cnf");
        fs::write(&leaf_config, "[req]\ndistinguished_name=dn\nprompt=no\n[dn]\nCN=localhost\n[leaf]\nsubjectAltName=IP:127.0.0.1\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth\n").unwrap();
        let request = root.join("leaf.csr");
        let output = ProcessCommand::new("openssl")
            .args(["req", "-new", "-key"])
            .arg(&key)
            .arg("-config")
            .arg(&leaf_config)
            .arg("-out")
            .arg(&request)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let leaf = root.join("leaf.pem");
        let output = ProcessCommand::new("openssl")
            .args(["x509", "-req", "-in"])
            .arg(request)
            .arg("-CA")
            .arg(&certificate)
            .arg("-CAkey")
            .arg(&key)
            .args(["-set_serial", "2", "-days", "1", "-extfile"])
            .arg(leaf_config)
            .args(["-extensions", "leaf", "-out"])
            .arg(&leaf)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let certificate = CertificateDer::from_pem_file(certificate).unwrap();
        let leaf = CertificateDer::from_pem_file(leaf).unwrap();
        let private_key = PrivateKeyDer::from_pem_file(&key).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(certificate.clone()).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::clone(&provider),
        )
        .build()
        .unwrap();
        let config = Arc::new(
            rustls::ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_client_cert_verifier(verifier)
                .with_single_cert(vec![leaf, certificate], private_key)
                .unwrap(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let mode = Arc::new(AtomicU8::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let (server_mode, server_stop, server_requests) =
            (Arc::clone(&mode), Arc::clone(&stop), Arc::clone(&requests));
        let task = thread::spawn(move || {
            while !server_stop.load(Ordering::Acquire) {
                let (socket, _) = match listener.accept() {
                    Ok(pair) => pair,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(error) => panic!("fixture accept: {error}"),
                };
                if server_mode.load(Ordering::Acquire) == 2 {
                    continue;
                }
                socket.set_nonblocking(false).unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
                let connection = rustls::ServerConnection::new(Arc::clone(&config)).unwrap();
                let mut stream = rustls::StreamOwned::new(connection, socket);
                let mut request = Vec::new();
                let mut buffer = [0u8; 4096];
                loop {
                    match stream.read(&mut buffer) {
                        Ok(0) => break,
                        Err(error) => {
                            std::eprintln!("fixture_tls_read_error detail={error}");
                            break;
                        }
                        Ok(size) => request.extend_from_slice(&buffer[..size]),
                    }
                    if let Some(header_end) =
                        request.windows(4).position(|part| part == b"\r\n\r\n")
                    {
                        let headers = String::from_utf8_lossy(&request[..header_end]);
                        let length = headers
                            .lines()
                            .find_map(|line| {
                                line.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .map(|value| value.trim().parse::<usize>().unwrap())
                            })
                            .unwrap_or(0);
                        if request.len() >= header_end + 4 + length {
                            break;
                        }
                    }
                }
                if request.is_empty() {
                    continue;
                }
                let request = String::from_utf8(request).unwrap();
                let configuration = request.starts_with("GET /auth/v1/runtime/configuration ");
                let profile = request.starts_with("GET /auth/v1/runtime/profile ");
                server_requests.lock().unwrap().push(request);
                let status =
                    if profile || (configuration && server_mode.load(Ordering::Acquire) == 0) {
                        "500 Internal Server Error"
                    } else if configuration {
                        "304 Not Modified"
                    } else {
                        "204 No Content"
                    };
                let response = format!("HTTP/1.1 {status}\r\nETag: \"sha256-{}\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", "b".repeat(64));
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
                stream.conn.send_close_notify();
                let _ = stream.flush();
            }
        });
        Self {
            address,
            mode,
            stop,
            requests,
            task: Some(task),
        }
    }
}

impl Drop for CloudFixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.task.take().unwrap().join().unwrap();
    }
}

#[test]
fn https_cloud_outage_304_and_recovery_preserve_grant_and_active_proof() {
    let (directory, activation_id) = activation_outcome_fixture("committed", None, 7);
    let root = directory.path();
    let cloud = CloudFixture::start(root);
    let identity_dir = root.join("identity");
    fs::create_dir(&identity_dir).unwrap();
    fs::set_permissions(&identity_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let mut device = identity();
    device.cloud_address = format!("https://{}", cloud.address);
    atomic_json(
        &identity_dir.join("device-identity-v1.json"),
        &device,
        0o600,
    )
    .unwrap();
    let mut pem = fs::read(root.join("key.pem")).unwrap();
    pem.extend(fs::read(root.join("leaf.pem")).unwrap());
    fs::write(identity_dir.join("device-mtls.pem"), pem).unwrap();
    fs::set_permissions(
        identity_dir.join("device-mtls.pem"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let descriptor = root
        .join("activations")
        .join(activation_id)
        .join("activation-v1.json");
    let mut grant: ActivationDescriptor =
        read_bounded_json(&descriptor, MAX_PROFILE_BYTES).unwrap();
    grant.grant_refresh_after_unix = unix_now().unwrap() + 30;
    grant.grant_expires_at_unix = unix_now().unwrap() + 60;
    atomic_json(&descriptor, &grant, 0o600).unwrap();
    let outcome = read_activation_ready_receipt(root).unwrap().unwrap();
    promote_committed_activation(root, &outcome).unwrap();
    clear_activation_ready_receipt(root).unwrap();
    let proof_path = root.join("active-activation-v1.json");
    let original_proof = fs::read(&proof_path).unwrap();
    let original_grant = fs::read(&descriptor).unwrap();
    let state = SyncState {
        schema_version: 1,
        etag: Some(grant.delivery_etag.clone()),
        configuration_sha256: Some(grant.delivery_sha256.clone()),
        projection_publication_id: Some(grant.projection_publication_id),
        projection_content_hash: Some(grant.projection_content_hash.clone()),
        activation_phase: Some("commit".into()),
        activation_required: true,
        ..SyncState::default()
    };
    atomic_json(&root.join("sync-state-v1.json"), &state, 0o600).unwrap();
    let mut args = args(root.to_owned(), false, Vec::new());
    args.run_dir = root.to_owned();
    args.ca_certificate = Some(root.join("ca.pem"));
    let invoke = |args: &Args| sync_once_with_retry(args, &[], true);
    let error = invoke(&args).unwrap_err();
    assert!(format!("{error:#}").contains("500"), "{error:#}");
    for mode in [1, 2, 1] {
        cloud.mode.store(mode, Ordering::Release);
        if mode == 2 {
            assert!(invoke(&args).is_err());
        } else {
            invoke(&args).unwrap();
        }
        assert_eq!(fs::read(&proof_path).unwrap(), original_proof);
        assert_eq!(
            fs::read(&descriptor).unwrap(),
            original_grant,
            "304 or WAN reset must not renew a grant"
        );
    }
    grant.grant_refresh_after_unix = unix_now().unwrap() - 1;
    grant.grant_expires_at_unix = unix_now().unwrap() - 1;
    atomic_json(&descriptor, &grant, 0o600).unwrap();
    assert!(
        invoke(&args).is_err(),
        "304 cannot reauthorize an expired candidate"
    );
    let requests = cloud.requests.lock().unwrap();
    let configuration = requests
        .iter()
        .filter(|request| request.starts_with("GET /auth/v1/runtime/configuration "))
        .collect::<Vec<_>>();
    assert!(configuration.len() >= 5);
    assert!(
        !configuration
            .last()
            .unwrap()
            .to_ascii_lowercase()
            .contains("if-none-match:"),
        "refresh must perform an unconditional fetch"
    );
    assert_eq!(fs::read(&proof_path).unwrap(), original_proof);
}
