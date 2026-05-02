import datetime
import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def create_cert(name, common_name, san_list):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Paladin Internal"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    
    san = x509.SubjectAlternativeName([x509.DNSName(n) for n in san_list])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=3650)
    ).add_extension(san, critical=False).sign(key, hashes.SHA256())
    
    os.makedirs(f"certs/{name}", exist_ok=True)
    with open(f"certs/{name}/server.key", "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open(f"certs/{name}/server.crt", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

if __name__ == "__main__":
    os.makedirs("certs", exist_ok=True)
    create_cert("neo4j", u"neo4j", [u"neo4j", u"localhost"])
    create_cert("postgres", u"postgres", [u"postgres", u"localhost"])
    print("Internal TLS certificates generated in certs/ directory.")
