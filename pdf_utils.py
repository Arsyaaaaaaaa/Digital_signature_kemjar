import os
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import signers
from pyhanko.sign.fields import SigFieldSpec, append_signature_field
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from PyPDF2 import PdfReader, PdfWriter

def sign_pdf(input_path, output_path, cert_path, key_path, signature_png_path, qr_path, signer_name, email):
    # 1. Create Overlay with Signature Info and QR
    overlay_pdf = "overlay_temp.pdf"
    c = canvas.Canvas(overlay_pdf, pagesize=letter)
    
    # Koordinat kotak tanda tangan (disesuaikan)
    box_x, box_y = 50, 50
    
    c.setFont("Helvetica-Bold", 6)
    c.drawString(box_x + 50, box_y + 42, "Ditandatangani Digital")
    c.setFont("Helvetica", 5)
    c.drawString(box_x + 50, box_y + 32, f"Nama : {signer_name}")
    c.drawString(box_x + 50, box_y + 24, f"Email : {email}")

    # Gambar QR Code
    if qr_path and os.path.exists(qr_path):
        c.drawImage(qr_path, box_x, box_y, width=45, height=45)

    # PNG tanda tangan di kanan
    if signature_png_path and os.path.exists(signature_png_path):
        c.drawImage(
            signature_png_path,
            box_x + 180,
            box_y + 5,
            width=40,
            height=20,
            mask='auto'
        )
    c.save()

    # 2. Merge Overlay dengan PDF Asli
    reader = PdfReader(input_path)
    writer = PdfWriter()
    overlay_reader = PdfReader(overlay_pdf)
    
    for i in range(len(reader.pages)):
        page = reader.pages[i]
        if i == 0:  # Tempel di halaman pertama
            page.merge_page(overlay_reader.pages[0])
        writer.add_page(page)

    temp_merged = "temp_merged.pdf"
    with open(temp_merged, "wb") as f:
        writer.write(f)

    # 3. Digital Signing menggunakan PyHanko (Invisble signature untuk validasi)
    signer = signers.SimpleSigner.load_pkcs12(pfx_file=cert_path.replace('_cert.pem', '.p12'), passphrase=b'')
    
    with open(temp_merged, 'rb') as inf:
        w = IncrementalPdfFileWriter(inf)
        with open(output_path, 'wb') as outf:
            signers.sign_pdf(w, signers.PdfSignatureMetadata(field_name='Signature1'), signer=signer, output=outf)
    
    # Cleanup
    if os.path.exists(overlay_pdf): os.remove(overlay_pdf)
    if os.path.exists(temp_merged): os.remove(temp_merged)