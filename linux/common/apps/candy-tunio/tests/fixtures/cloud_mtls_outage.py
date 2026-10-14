"""Isolated mTLS Cloud HTTP failure fixture; no production credentials."""
import http.server
import json
import os
import pathlib
import ssl
import subprocess
import sys

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


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        peer = bool(self.connection.getpeercert())
        with (root / "requests.jsonl").open("a") as output:
            output.write(json.dumps({"path": self.path, "authenticated_client_certificate": peer, "response": 500}) + "\n")
        self.send_response(500)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *_):
        pass


server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(str(root / "leaf.pem"), str(root / "key.pem"))
context.load_verify_locations(str(root / "ca.pem"))
context.verify_mode = ssl.CERT_REQUIRED
server.socket = context.wrap_socket(server.socket, server_side=True)
device = {"schema_version": 1, "cloud_address": f"https://127.0.0.1:{server.server_port}", "organization_id": "11111111-1111-1111-1111-111111111111", "tenant_id": "22222222-2222-2222-2222-222222222222", "site_id": "33333333-3333-3333-3333-333333333333", "display_name": "isolated-mtls-gate", "device_id": "44444444-4444-4444-4444-444444444444", "device_key_id": "55555555-5555-5555-5555-555555555555", "not_after": "2099-01-01T00:00:00Z"}
(identity / "device-identity-v1.json").write_text(json.dumps(device))
os.chmod(identity / "device-identity-v1.json", 0o600)
(root / "ready.json").write_text(json.dumps({"port": server.server_port, "client_certificate_required": True}))
server.serve_forever()
