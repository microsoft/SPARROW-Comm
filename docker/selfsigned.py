"""Write a self-signed certificate and key for the local FTPS server (development only)."""

import datetime as dt
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

out = Path(sys.argv[1] if len(sys.argv) > 1 else "certs")
out.mkdir(parents=True, exist_ok=True)
cert_path, key_path = out / "cert.pem", out / "key.pem"
if cert_path.exists() and key_path.exists():
    print(f"exists: {cert_path}")
    sys.exit(0)
key = ec.generate_private_key(ec.SECP256R1())
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
now = dt.datetime.now(dt.UTC)
cert = (
    x509.CertificateBuilder()
    .subject_name(name)
    .issuer_name(name)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now - dt.timedelta(minutes=5))
    .not_valid_after(now + dt.timedelta(days=365))
    .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.DNSName("ftps")]), False)
    .sign(key, hashes.SHA256())
)
cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
key_path.write_bytes(
    key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
)
key_path.chmod(0o600)
print(f"wrote: {cert_path}")
