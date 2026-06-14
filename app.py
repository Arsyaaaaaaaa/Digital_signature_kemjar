from flask import Flask, render_template, request, redirect, session, send_file, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp
import qrcode
import os
import uuid
from datetime import datetime
from crypto_utils import generate_root_ca, generate_user_certificate
from pdf_utils import sign_pdf
from pyhanko.pdf_utils.reader import PdfFileReader
import socket
import ipaddress
import datetime as dt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
os.chdir(BASE_DIR)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)


class User(db.Model):
    id               = db.Column(db.Integer, primary_key=True)
    name             = db.Column(db.String(100))
    email            = db.Column(db.String(100), unique=True)
    password         = db.Column(db.String(255))
    otp_secret       = db.Column(db.String(32))
    certificate_path = db.Column(db.String(255))
    private_key_path = db.Column(db.String(255))
    digital_status   = db.Column(db.String(20), default="none")
    signature_png    = db.Column(db.String(255))

with app.app_context():
    db.create_all()


ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"


@app.route('/')
def home():
    return redirect('/login')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name     = request.form['name']
        email    = request.form['email']
        password = request.form['password']
        hashed   = generate_password_hash(password)

        if User.query.filter_by(email=email).first():
            return "Email sudah terdaftar"

        # Buat OTP secret langsung saat register
        otp_secret = pyotp.random_base32()
        user = User(name=name, email=email, password=hashed, otp_secret=otp_secret)
        db.session.add(user)
        db.session.commit()

        # Simpan session sementara untuk setup OTP
        session['pending_user_id'] = user.id
        return redirect('/setup-otp')

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login_type = request.form.get('login_type', 'user')
        email      = request.form['email']
        password   = request.form['password']

        
        if login_type == 'admin':
            if email == ADMIN_USERNAME and password == ADMIN_PASSWORD:
                session.clear()
                session['admin'] = True
                return redirect('/admin/dashboard')
            return render_template('login.html', error="Login admin gagal. Periksa username/password.")

        
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session.clear()
            session['user_id']    = user.id
            # otp_verified TIDAK diset di sini — user harus lewat OTP dulu

            
            if not user.otp_secret:
                user.otp_secret = pyotp.random_base32()
                db.session.commit()

            
            _generate_qr(user)

            return redirect('/setup-otp')

        return render_template('login.html', error="Email atau password salah.")

    return render_template('login.html', error=None)


def _generate_qr(user):
    os.makedirs("static/qr", exist_ok=True)
    totp    = pyotp.TOTP(user.otp_secret)
    uri     = totp.provisioning_uri(name=user.email, issuer_name="DigitalSign App")
    qr_path = f"static/qr/{user.id}.png"
    qrcode.make(uri).save(qr_path)
    return qr_path


@app.route('/setup-otp')
def setup_otp():
    # Bisa diakses dari login (user_id) atau register (pending_user_id)
    user_id = session.get('user_id') or session.get('pending_user_id')
    if not user_id:
        return redirect('/login')

    user = User.query.get(user_id)
    if not user:
        return redirect('/login')

    # Pastikan ada OTP secret
    if not user.otp_secret:
        user.otp_secret = pyotp.random_base32()
        db.session.commit()

    # Simpan user_id ke session supaya verify-otp bisa mengaksesnya
    session['user_id'] = user.id

    qr_path = _generate_qr(user)

    return render_template("otp_setup.html", qr_path=qr_path, user=user)


@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if 'user_id' not in session:
        return redirect('/login')

    user = User.query.get(session['user_id'])
    if not user:
        return redirect('/login')

    error = None
    if request.method == 'POST':
        otp  = request.form.get('otp', '').strip()
        totp = pyotp.TOTP(user.otp_secret)

        # valid_window=1 → toleransi ±30 detik
        if totp.verify(otp, valid_window=1):
            session['otp_verified'] = True
            session.pop('pending_user_id', None)
            return redirect('/dashboard')
        else:
            error = "Kode OTP salah atau sudah kedaluwarsa. Silakan coba lagi."

    return render_template('verify_otp.html', error=error, user=user)


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/login')
    if not session.get('otp_verified'):
        return redirect('/setup-otp')

    user = User.query.get(session['user_id'])
    return render_template('dashboard.html', user=user)


@app.route('/request-digital-id')
def request_digital_id():
    if 'user_id' not in session:
        return redirect('/login')
    user = User.query.get(session['user_id'])
    user.digital_status = "pending"
    db.session.commit()
    return redirect('/dashboard')


@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('admin'):
        return redirect('/login')
    pending_users  = User.query.filter_by(digital_status='pending').all()
    approved_users = User.query.filter_by(digital_status='approved').all()
    return render_template('admin_dashboard.html',
                           pending_users=pending_users,
                           approved_users=approved_users)

@app.route('/admin/approve/<int:user_id>')
def approve(user_id):
    if not session.get('admin'):
        return redirect('/login')
    user = User.query.get_or_404(user_id)
    user.digital_status = "approved"
    key_path, cert_path, p12_path = generate_user_certificate(user.id, user.name, user.email)
    user.private_key_path = key_path
    user.certificate_path = cert_path
    db.session.commit()
    return redirect('/admin/dashboard')


@app.route('/upload-signature', methods=['POST'])
def upload_signature():
    if 'user_id' not in session:
        return redirect('/login')
    file = request.files['signature']
    os.makedirs("uploads/signature", exist_ok=True)
    path = f"uploads/signature/user_{session['user_id']}.png"
    file.save(path)
    user = User.query.get(session['user_id'])
    user.signature_png = path
    db.session.commit()
    return redirect('/dashboard')


@app.route('/sign-pdf', methods=['POST'])
def sign_pdf_route():
    if 'user_id' not in session:
        return redirect('/login')
    if not session.get('otp_verified'):
        return redirect('/setup-otp')

    file = request.files['pdf']
    if not file or file.filename == '':
        return "Pilih file PDF terlebih dahulu."

    os.makedirs("uploads/original", exist_ok=True)
    os.makedirs("uploads/signed", exist_ok=True)
    os.makedirs("static/qr", exist_ok=True)

    # Nama file unik menggunakan UUID
    file_uuid   = uuid.uuid4().hex
    input_path  = f"uploads/original/{file_uuid}_{file.filename}"
    output_path = f"uploads/signed/{file_uuid}_signed_{file.filename}"
    file.save(input_path)

    user = User.query.get(session['user_id'])
    if user.digital_status != "approved":
        return "Digital ID belum diapprove admin. Minta admin untuk approve terlebih dahulu."

    verification_id = str(uuid.uuid4())[:8]
    qr_text = (f"DGSign Verification\nName: {user.name}\n"
               f"Email: {user.email}\nVerification ID: {verification_id}\n"
               f"Date: {datetime.now()}")

    qr_path = f"static/qr/sign_{user.id}.png"
    qr = qrcode.QRCode(version=1, box_size=6, border=2)
    qr.add_data(qr_text)
    qr.make(fit=True)
    qr.make_image(fill_color="black", back_color="white").save(qr_path)

    sign_pdf(
        input_path, output_path,
        user.certificate_path, user.private_key_path,
        user.signature_png, qr_path,
        user.name, user.email
    )

    return send_file(output_path, as_attachment=True,
                     download_name=f"signed_{file.filename}")



@app.route('/verify-signature', methods=['GET', 'POST'])
def verify_signature():
    result = None
    if request.method == 'POST':
        if 'signed_pdf' in request.files:
            file = request.files['signed_pdf']
            if file.filename != '':
                os.makedirs("uploads/verify", exist_ok=True)
                # Nama unik agar tidak tertimpa
                file_uuid = uuid.uuid4().hex
                path = f"uploads/verify/{file_uuid}_{file.filename}"
                file.save(path)
                try:
                    with open(path, 'rb') as f:
                        reader = PdfFileReader(f)
                        if reader.embedded_signatures:
                            result = "✅ Dokumen telah ditandatangani secara digital."
                        else:
                            result = "❌ Dokumen belum ditandatangani secara digital."
                except Exception as e:
                    result = f"Error membaca file: {str(e)}"
            else:
                result = "Silakan pilih file terlebih dahulu."
    return render_template("verify_signature.html", verification_result=result)


@app.route('/download-p12')
def download_p12():
    if 'user_id' not in session:
        return redirect('/login')
    user = User.query.get(session['user_id'])
    path = f"certificates/users/user_{user.id}.p12"
    if os.path.exists(path):
        return send_file(path, as_attachment=True,
                         download_name=f"sertifikat_{user.name}.p12")
    return "File .p12 tidak ditemukan. Minta admin untuk approve Digital ID Anda."


@app.route('/download-ca')
def download_ca():
    # File .cer lebih gampang diimport ke Windows Trusted Root.
    path_cer = "certificates/root_ca_cert.cer"
    path_pem = "certificates/root_ca_cert.pem"
    if os.path.exists(path_cer):
        return send_file(path_cer, as_attachment=True, download_name="DGSign_Root_CA.cer")
    if os.path.exists(path_pem):
        return send_file(path_pem, as_attachment=True, download_name="DGSign_Root_CA.crt")
    return "Root CA tidak ditemukan."


@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')



def detect_lan_ip():
    """Ambil IP Wi-Fi/LAN laptop agar QR bisa dibuka HP satu jaringan."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
        sock.close()
        if ip and not ip.startswith("127."):
            return ip
    except Exception:
        pass
    return "127.0.0.1"


def _verify_chain_python(ca_cert_path: str, server_cert_path: str) -> bool:
    """
    Verifikasi bahwa server_cert ditandatangani oleh CA di ca_cert_path.
    Menggunakan cryptography library murni — tidak butuh openssl.exe.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography import exceptions as crypto_exc

        with open(ca_cert_path, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())
        with open(server_cert_path, "rb") as f:
            srv_cert = x509.load_pem_x509_certificate(f.read())

        # Cek issuer server cert == subject CA cert
        if srv_cert.issuer != ca_cert.subject:
            return False

        # Verifikasi tanda tangan menggunakan public key CA
        ca_pub = ca_cert.public_key()
        ca_pub.verify(
            srv_cert.signature,
            srv_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            srv_cert.signature_hash_algorithm,
        )
        return True
    except Exception:
        return False


def generate_https_server_certificate(lan_ip):
    """
    Membuat server certificate untuk HTTPS Flask.
    - Server cert DITANDATANGANI oleh Root CA (bukan self-signed).
    - Jika file sudah ada DAN chain valid, TIDAK di-regenerate agar
      CA yang sudah diimport ke Windows tetap berlaku.
    - SAN: localhost, 127.0.0.1, ::1, + IP LAN.
    """
    os.makedirs("certificates", exist_ok=True)
    ca_key_path   = "certificates/root_ca_key.pem"
    ca_cert_path  = "certificates/root_ca_cert.pem"
    ca_cer_path   = "certificates/root_ca_cert.cer"
    ssl_key_path  = "certificates/ssl_server_key.pem"
    ssl_cert_path = "certificates/ssl_server_cert.pem"

    # Pastikan Root CA ada
    generate_root_ca()

    # Buat .cer (DER) untuk import Windows — selalu refresh agar sync
    with open(ca_cert_path, "rb") as f:
        ca_cert_obj = x509.load_pem_x509_certificate(f.read())
    with open(ca_cer_path, "wb") as f:
        f.write(ca_cert_obj.public_bytes(serialization.Encoding.DER))

    # ── Cek apakah server cert sudah ada DAN rantainya valid ──
    # Pakai Python murni — tidak butuh openssl.exe (aman di Windows)
    if os.path.exists(ssl_cert_path) and os.path.exists(ssl_key_path):
        if _verify_chain_python(ca_cert_path, ssl_cert_path):
            print("[SSL] Sertifikat server sudah ada dan valid. Tidak di-regenerate.")
            _tulis_info_ssl(lan_ip, ssl_cert_path)
            return ssl_cert_path, ssl_key_path
        else:
            print("[SSL] Sertifikat server ada tapi chain tidak valid. Membuat ulang...")

    # ── Generate server certificate baru ──
    with open(ca_key_path, "rb") as f:
        ca_private_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "ID"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "DGSign"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])

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
        .issuer_name(ca_cert.subject)                          # <-- Root CA sebagai issuer
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=825))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(san_items), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_private_key.public_key()),
            critical=False
        )
        .sign(ca_private_key, hashes.SHA256())                 # <-- Ditandatangani Root CA
    )

    with open(ssl_key_path, "wb") as f:
        f.write(server_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open(ssl_cert_path, "wb") as f:
        f.write(server_cert.public_bytes(serialization.Encoding.PEM))

    print("[SSL] Server certificate baru berhasil dibuat dan ditandatangani Root CA.")
    _tulis_info_ssl(lan_ip, ssl_cert_path)
    return ssl_cert_path, ssl_key_path


def _tulis_info_ssl(lan_ip, ssl_cert_path):
    """Tulis file info HTTPS agar user tahu URL yang bisa dibuka."""
    with open("HTTPS_INFO.txt", "w", encoding="utf-8") as f:
        f.write("=" * 55 + "\n")
        f.write("  DGSign HTTPS — Panduan Akses & Install CA\n")
        f.write("=" * 55 + "\n\n")
        f.write("Buka di browser laptop:\n")
        f.write("  https://localhost:5000\n")
        f.write("  https://127.0.0.1:5000\n")
        f.write(f"  https://{lan_ip}:5000   (HP satu Wi-Fi)\n\n")
        f.write("── CARA INSTALL ROOT CA KE WINDOWS ──────────────\n")
        f.write("File yang perlu diimport:\n")
        f.write("  certificates/root_ca_cert.cer\n\n")
        f.write("Langkah:\n")
        f.write("  1. Double-click  root_ca_cert.cer\n")
        f.write("  2. Klik  [Install Certificate]\n")
        f.write("  3. Pilih  Local Machine  → Next\n")
        f.write("  4. Pilih  'Place all certificates in the following store'\n")
        f.write("  5. Browse → Trusted Root Certification Authorities → OK\n")
        f.write("  6. Finish → Yes (konfirmasi UAC jika muncul)\n")
        f.write("  7. TUTUP SEMUA TAB CHROME/EDGE lalu buka ulang\n\n")
        f.write("PENTING: Setiap kali Root CA di-regenerate (hapus folder\n")
        f.write("certificates/) Anda harus install ulang CA ke Windows.\n")
        f.write("Selama folder certificates/ tidak dihapus, CA tidak berubah.\n")


if __name__ == '__main__':
    os.makedirs("certificates/users", exist_ok=True)
    os.makedirs("uploads/original", exist_ok=True)
    os.makedirs("uploads/signed", exist_ok=True)
    os.makedirs("uploads/signature", exist_ok=True)
    os.makedirs("static/qr", exist_ok=True)

    lan_ip = detect_lan_ip()
    ssl_cert, ssl_key = generate_https_server_certificate(lan_ip)

    print("\nDGSign HTTPS Self-Made SSL")
    print("Buka di laptop : https://localhost:5000")
    print("Alternatif     : https://127.0.0.1:5000")
    print(f"HP satu Wi-Fi  : https://{lan_ip}:5000")
    print("Kalau masih merah, import certificates/root_ca_cert.cer ke Trusted Root lalu restart Chrome.\n")

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True,
        ssl_context=(ssl_cert, ssl_key)
    )
