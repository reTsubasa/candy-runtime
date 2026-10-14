"""Isolated mTLS Cloud outage/renewal fixture; no production credentials.

The optional signed fixture is owned by the Cloud signer, never the client's
active authority. Runtime consumes renewed envelopes only through HTTPS.
"""
import base64
import hashlib
import http.server
import json
import os
import pathlib
import ssl
import subprocess
import sys
import struct
import threading
import uuid

root = pathlib.Path(sys.argv[1])
root.mkdir(mode=0o700)
identity = root / "identity"
identity.mkdir(mode=0o700)
config = root / "tls.cnf"
config.write_text("[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n[dn]\nCN=Candy Isolated Test CA\n[ext]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,digitalSignature,keyCertSign,keyEncipherment\n")
subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "7", "-config", str(config), "-keyout", str(root / "key.pem"), "-out", str(root / "ca.pem")], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
leaf_config = root / "leaf.cnf"
leaf_config.write_text("[req]\ndistinguished_name=dn\nprompt=no\n[dn]\nCN=localhost\n[leaf]\nsubjectAltName=IP:127.0.0.1\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth\n")
subprocess.run(["openssl", "req", "-new", "-key", str(root / "key.pem"), "-config", str(leaf_config), "-out", str(root / "leaf.csr")], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
subprocess.run(["openssl", "x509", "-req", "-in", str(root / "leaf.csr"), "-CA", str(root / "ca.pem"), "-CAkey", str(root / "key.pem"), "-set_serial", "2", "-days", "7", "-extfile", str(leaf_config), "-extensions", "leaf", "-out", str(root / "leaf.pem")], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
mtls = identity / "device-mtls.pem"
mtls.write_bytes((root / "key.pem").read_bytes() + (root / "leaf.pem").read_bytes())
os.chmod(mtls, 0o600)
fixture = pathlib.Path(sys.argv[2]) if len(sys.argv) > 2 else None
core = sys.argv[3] if fixture else None
signer = sys.argv[4] if fixture else None
issue_lock = threading.Lock()
issued = {}
configuration = None
etag = None
report = None


def identifier(number):
    return str(uuid.UUID(bytes=bytes([number]) * 16))


def core_report(projection):
    return json.loads(subprocess.check_output([core, "client", "sdwan", "verify-control", "--segment-snapshot", str(fixture / "segment.snapshot"), "--site-projection", str(fixture / projection), "--route-signing-public-key", (fixture / "route-public-key.txt").read_text().strip(), "--route-signing-key-id", "route-key-1"]))


if fixture:
    report = core_report("site.projection")
    peer = core_report("server.projection")
    b64 = lambda data: base64.urlsafe_b64encode(data).decode().rstrip("=")
    peer_meta = {"projection_id": str(uuid.UUID(peer["projection_id"])), "projection_generation": peer["projection_generation"], "projection_content_hash": peer["projection_content_hash"], "site_projection": b64((fixture / "server.projection").read_bytes())}
    configuration = {"schema_version": 1, "activation_phase": "commit", "projection_publication_id": identifier(33), "projection_id": str(uuid.UUID(report["projection_id"])), "segment_id": str(uuid.UUID(report["segment_id"])), "attachment_id": str(uuid.UUID(report["attachment_id"])), "segment_generation": report["segment_generation"], "projection_generation": report["projection_generation"], "projection_content_hash": report["projection_content_hash"], "route_signing_key_id": "route-key-1", "route_signing_public_key": (fixture / "route-public-key.txt").read_text().strip(), "segment_snapshot": b64((fixture / "segment.snapshot").read_bytes()), "site_projection": b64((fixture / "site.projection").read_bytes()), "peer_projection_catalog": [peer_meta], "compatibility_generations": [], "grant_verification_keys": [{"key_id": "cloud-key", "ed25519_public_key": (fixture / "cloud-public-key.txt").read_text().strip(), "issuer_id": identifier(21), "environment_id": identifier(22)}]}
    u64 = lambda value: struct.pack(">Q", value)
    objects = hashlib.sha256(b"candy/runtime-configuration-v1\0")
    for name in ["segment.snapshot", "site.projection"]:
        raw = (fixture / name).read_bytes(); objects.update(u64(len(raw))); objects.update(raw)
    objects.update(u64(1)); objects.update(uuid.UUID(peer_meta["projection_id"]).bytes); objects.update(u64(peer_meta["projection_generation"])); objects.update(bytes.fromhex(peer_meta["projection_content_hash"])); raw = (fixture / "server.projection").read_bytes(); objects.update(u64(len(raw))); objects.update(raw); objects.update(u64(0))
    delivery = hashlib.sha256(b"candy/runtime-delivery-v1\0" + objects.digest() + b"commit")
    key_id = b"route-key-1"; delivery.update(u64(len(key_id))); delivery.update(key_id); delivery.update(bytes.fromhex(configuration["route_signing_public_key"])); delivery.update(u64(1))
    key = configuration["grant_verification_keys"][0]; key_id = key["key_id"].encode(); delivery.update(u64(len(key_id))); delivery.update(key_id); delivery.update(bytes.fromhex(key["ed25519_public_key"])); delivery.update(uuid.UUID(key["issuer_id"]).bytes); delivery.update(uuid.UUID(key["environment_id"]).bytes)
    etag = '"sha256-' + delivery.hexdigest() + '"'
    seed = (fixture / "device.key").read_bytes()
    raw_key = identity / "operational-key.der"; raw_key.write_bytes(bytes.fromhex("302e020100300506032b657004220420") + seed)
    subprocess.run(["openssl", "pkey", "-inform", "DER", "-in", str(raw_key), "-out", str(identity / "operational-key.pem")], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    os.chmod(identity / "operational-key.pem", 0o600)
    (root / "mode").write_text("healthy")


class Handler(http.server.BaseHTTPRequestHandler):
    def response(self, status, body=b"", content_type="application/json"):
        with (root / "requests.jsonl").open("a") as output:
            output.write(json.dumps({"path": self.path, "method": self.command, "authenticated_client_certificate": bool(self.connection.getpeercert()), "response": status}) + "\n")
        self.send_response(status); self.send_header("Content-Type", content_type); self.send_header("Content-Length", str(len(body)))
        if etag: self.send_header("ETag", etag)
        self.end_headers(); self.wfile.write(body)

    def do_GET(self):
        if fixture and (root / "mode").read_text().strip() == "healthy" and self.path == "/auth/v1/runtime/configuration":
            if self.headers.get("If-None-Match") == etag: self.response(304)
            else: self.response(200, json.dumps(configuration).encode(), "application/vnd.candy.runtime-configuration.v1+json")
        else: self.response(500)

    def do_PUT(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if self.path != "/auth/v1/runtime/configuration/status": return self.response(404)
        with (root / "publication-status.jsonl").open("a") as output: output.write(body.decode() + "\n")
        self.response(204)

    def do_POST(self):
        request = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
        if not fixture or (root / "mode").read_text().strip() != "healthy": return self.response(500)
        if self.path != "/auth/v1/access-grants": return self.response(404)
        assert request["node_pool_id"] == identifier(3) and request["service_permission"] == "private.tun.connect" and request["service_class"] == "private"
        with issue_lock:
            replayed = request["request_id"] in issued
            if not replayed:
                env = dict(os.environ, CANDY_SIGNED_FIXTURE_RENEW_ROOT=str(fixture), CANDY_SIGNED_FIXTURE_GRANT_TTL_SECS="30")
                subprocess.run([signer], env=env, check=True, stdout=subprocess.DEVNULL)
                args = [core, "client", "sdwan", "verify-grant", "--grant", str(fixture / "grant.bin"), "--public-key", configuration["grant_verification_keys"][0]["ed25519_public_key"], "--key-id", "cloud-key", "--issuer-id", identifier(21), "--environment-id", identifier(22), "--tenant-id", str(uuid.UUID(report["tenant_id"])), "--device-id", str(uuid.UUID(report["device_id"])), "--device-key-id", str(uuid.UUID(report["device_key_id"])), "--node-pool-id", identifier(3), "--projection-id", configuration["projection_id"], "--projection-generation", str(report["projection_generation"]), "--projection-content-hash", report["projection_content_hash"]]
                verified = json.loads(subprocess.check_output(args))
                issued[request["request_id"]] = {"grant_id": verified["grant_id"], "expires_at_unix": verified["expires_at_unix"], "refresh_after_unix": verified["refresh_after_unix"], "replayed": False, "access_grant": base64.urlsafe_b64encode((fixture / "grant.bin").read_bytes()).decode().rstrip("=")}
            body = dict(issued[request["request_id"]], replayed=replayed)
            with (root / "issuance.jsonl").open("a") as output: output.write(json.dumps({"request_id": request["request_id"], "grant_id": body["grant_id"], "expires_at_unix": body["expires_at_unix"], "replayed": replayed}) + "\n")
            self.response(200, json.dumps(body).encode())

    def log_message(self, *_):
        pass


server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(str(root / "leaf.pem"), str(root / "key.pem"))
context.load_verify_locations(str(root / "ca.pem"))
context.verify_mode = ssl.CERT_REQUIRED
server.socket = context.wrap_socket(server.socket, server_side=True)
device = {"schema_version": 1, "cloud_address": f"https://127.0.0.1:{server.server_port}", "organization_id": "11111111-1111-1111-1111-111111111111", "tenant_id": "22222222-2222-2222-2222-222222222222", "site_id": "33333333-3333-3333-3333-333333333333", "display_name": "isolated-mtls-gate", "device_id": "44444444-4444-4444-4444-444444444444", "device_key_id": "55555555-5555-5555-5555-555555555555", "not_after": "2099-01-01T00:00:00Z"}
if fixture:
    for name in ["tenant_id", "site_id", "device_id", "device_key_id"]: device[name] = str(uuid.UUID(report[name]))
(identity / "device-identity-v1.json").write_text(json.dumps(device))
os.chmod(identity / "device-identity-v1.json", 0o600)
(root / "ready.json").write_text(json.dumps({"port": server.server_port, "client_certificate_required": True}))
server.serve_forever()
