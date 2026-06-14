"""
setup_ssl.py — Generate SSL Certificate + Trust otomatis di Windows
=====================================================================
Jalankan sekali sebelum `python app.py`:
    python setup_ssl.py

Script ini akan:
  1. Generate Root CA (sekali, disimpan di certificates/)
  2. Generate server certificate (ditandatangani Root CA, ada SAN)
  3. Export Root CA ke .cer untuk Windows
  4. (Opsional) Auto-trust Root CA ke Windows Trusted Root Store lewat PowerShell
"""

import os
import sys
import subprocess
import platform
import socket
import ipaddress
import datetime as dt

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

CERT_DIR = "certificates"
ROOT_CA_KEY  = os.path.join(CERT_DIR, "root_ca_key.pem")
ROOT_CA_CERT = os.path.join(CERT_DIR, "root_ca_cert.pem")
ROOT_CA_CER  = os.path.join(CERT_DIR, "root_ca_cert.cer")   # format DER untuk Windows
SERVER_KEY   = os.path.join(CERT_DIR, "ssl_server_key.pem")
SERVER_CERT  = os.path.join(CERT_DIR, "ssl_server_cert.pem")



def detect_lan_ip() -> str:
    """Cari IP LAN laptop (bukan 127.x.x.x)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"




def generate_root_ca():
    """Buat Root CA baru jika belum ada."""
    os.makedirs(CERT_DIR, exist_ok=True)

    if os.path.exists(ROOT_CA_KEY) and os.path.exists(ROOT_CA_CERT):
        print("[CA] Root CA sudah ada, skip generate.")
        return

    print("[CA] Membuat Root CA baru …")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME,              "ID"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME,    "Jawa Barat"),
        x509.NameAttribute(NameOID.LOCALITY_NAME,             "Bandung"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME,         "Institut Teknologi Bandung"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME,  "DGSign PKI"),
        x509.NameAttribute(NameOID.COMMON_NAME,               "DGSign Root CA"),
    ])

    now = dt.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=3650))   # 10 tahun
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False, data_encipherment=False,
                key_agreement=False, encipher_only=False, decipher_only=False
            ), critical=True
        )
        .sign(key, hashes.SHA256())
    )

    with open(ROOT_CA_KEY, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        ))

    with open(ROOT_CA_CERT, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    # Export .cer (DER) untuk Windows
    with open(ROOT_CA_CER, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.DER))

    print(f"[CA] Root CA tersimpan di  {ROOT_CA_CERT}")
    print(f"[CA] File Windows .cer     {ROOT_CA_CER}")



def generate_server_cert(lan_ip: str):
    """Buat server cert baru, ditandatangani Root CA, dengan SAN lengkap."""
    os.makedirs(CERT_DIR, exist_ok=True)

    # Load Root CA
    with open(ROOT_CA_KEY, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(ROOT_CA_CERT, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    print(f"[SSL] Membuat server certificate (LAN: {lan_ip}) …")

    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME,     "ID"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME,"DGSign"),
        x509.NameAttribute(NameOID.COMMON_NAME,      "localhost"),
    ])

    # Subject Alternative Names (SAN) — WAJIB untuk Chrome modern
    san_items = [
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        x509.IPAddress(ipaddress.ip_address("::1")),
    ]
    try:
        ip_obj = ipaddress.ip_address(lan_ip)
        if str(ip_obj) != "127.0.0.1":
            san_items.append(x509.IPAddress(ip_obj))
    except ValueError:
        pass

    now = dt.datetime.utcnow()
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now  + dt.timedelta(days=825))   # max Chrome
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(san_items), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )

    with open(SERVER_KEY, "wb") as f:
        f.write(server_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        ))

    with open(SERVER_CERT, "wb") as f:
        f.write(server_cert.public_bytes(serialization.Encoding.PEM))

    print(f"[SSL] Server cert tersimpan di {SERVER_CERT}")



def trust_ca_windows():
    """
    Import Root CA ke Trusted Root store Windows secara otomatis.
    Butuh hak Administrator — PowerShell akan minta UAC.
    """
    if platform.system() != "Windows":
        print("[TRUST] Bukan Windows, skip auto-trust.")
        print(f"[TRUST] Kalau Linux/Mac, jalankan manual: lihat README di bawah.")
        return

    cer_abs = os.path.abspath(ROOT_CA_CER)
    if not os.path.exists(cer_abs):
        print(f"[TRUST] File .cer tidak ditemukan: {cer_abs}")
        return

    print("[TRUST] Mengimport Root CA ke Windows Trusted Root …")
    print("        (Mungkin muncul dialog UAC, klik Yes)")

    # Pakai PowerShell Import-Certificate
    ps_cmd = (
        f"Import-Certificate "
        f"-FilePath '{cer_abs}' "
        f"-CertStoreLocation Cert:\\LocalMachine\\Root"
    )

    try:
        result = subprocess.run(
            ["powershell", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            print("[TRUST] ✅ Root CA berhasil ditambahkan ke Trusted Root!")
            print("[TRUST] Tutup semua Chrome/Edge lalu buka ulang.")
        else:
            print("[TRUST] ❌ Gagal auto-trust. Error:")
            print(result.stderr)
            print()
            print("[TRUST] Coba manual lewat PowerShell Administrator:")
            print(f'  Import-Certificate -FilePath "{cer_abs}" -CertStoreLocation Cert:\\LocalMachine\\Root')
    except FileNotFoundError:
        print("[TRUST] PowerShell tidak ditemukan.")
    except subprocess.TimeoutExpired:
        print("[TRUST] Timeout — coba manual.")



def main():
    print("=" * 55)
    print("  DGSign SSL Setup")
    print("=" * 55)

    lan_ip = detect_lan_ip()
    print(f"[NET] LAN IP terdeteksi: {lan_ip}\n")

    # Step 1: Root CA
    generate_root_ca()

    # Step 2: Server certificate
    generate_server_cert(lan_ip)

    # Step 3: Auto-trust (Windows only)
    print()
    trust = input("Auto-trust Root CA ke Windows sekarang? (y/n): ").strip().lower()
    if trust == "y":
        trust_ca_windows()
    else:
        print("[TRUST] Skip. Lihat panduan manual di bawah.")

    # Ringkasan
    print()
    print("=" * 55)
    print("  SELESAI — Langkah selanjutnya:")
    print("=" * 55)
    print()
    print("  1. Jalankan app:")
    print("     python app.py")
    print()
    print("  2. Buka browser:")
    print("     https://localhost:5000")
    print(f"     https://{lan_ip}:5000   (HP satu Wi-Fi)")
    print()
    print("  Kalau masih merah (manual trust Windows):")
    cer_abs = os.path.abspath(ROOT_CA_CER)
    print(f'  Import-Certificate -FilePath "{cer_abs}" -CertStoreLocation Cert:\\LocalMachine\\Root')
    print()
    print("  Kalau manual trust Mac/Linux — lihat PANDUAN_SSL.md")


if __name__ == "__main__":
    main()
