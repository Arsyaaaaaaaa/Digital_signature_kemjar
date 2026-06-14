from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    NoEncryption,
    pkcs12,
    load_pem_private_key
)
import datetime
import os


def generate_root_ca():

    os.makedirs("certificates", exist_ok=True)

    key_path = "certificates/root_ca_key.pem"
    cert_path = "certificates/root_ca_cert.pem"

    if os.path.exists(key_path) and os.path.exists(cert_path):
        return

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "ID"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Jawa Barat"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Bandung"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Institut Teknologi Bandung"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "DGSign PKI"),
        x509.NameAttribute(NameOID.COMMON_NAME, "DGSign Root CA")
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(
            datetime.datetime.utcnow() +
            datetime.timedelta(days=3650)
        )
        .add_extension(
            x509.BasicConstraints(
                ca=True,
                path_length=None
            ),
            critical=True
        )
        .sign(
            private_key,
            hashes.SHA256()
        )
    )

    with open(key_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=NoEncryption()
            )
        )

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(Encoding.PEM))


def generate_user_certificate(user_id, name, email):

    os.makedirs("certificates/users", exist_ok=True)

    key_path = f"certificates/users/user_{user_id}_key.pem"
    cert_path = f"certificates/users/user_{user_id}_cert.pem"
    p12_path = f"certificates/users/user_{user_id}.p12"

    with open("certificates/root_ca_key.pem", "rb") as f:
        ca_private_key = load_pem_private_key(
            f.read(),
            password=None
        )

    with open("certificates/root_ca_cert.pem", "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(
            f.read()
        )

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "ID"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "DGSign User"),
        x509.NameAttribute(NameOID.COMMON_NAME, name),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, email)
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(
            datetime.datetime.utcnow() +
            datetime.timedelta(days=365)
        )
        .sign(
            ca_private_key,
            hashes.SHA256()
        )
    )

    with open(key_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=NoEncryption()
            )
        )

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(Encoding.PEM))

    p12_data = pkcs12.serialize_key_and_certificates(
        name=name.encode(),
        key=private_key,
        cert=cert,
        cas=[ca_cert],
        encryption_algorithm=NoEncryption()
    )

    with open(p12_path, "wb") as f:
        f.write(p12_data)

    return key_path, cert_path, p12_path