from flask import Flask, render_template, request, send_from_directory, redirect, send_file
import os
import io
from werkzeug.exceptions import RequestEntityTooLarge
import piexif
from PIL import Image

# -------------------- MODULE IMPORTS --------------------
from modules.ctf_helpers.decoder import decode_text
from modules.ctf_helpers.base_detector import detect_base
from modules.ctf_helpers.magic_decoder import magic_auto_decode
from modules.ctf_helpers.caesar_cracker import caesar_brute_force
from modules.ctf_helpers.hash_identifier import identify_hash


# Digital Forensics
from modules.digital_forensics.analyze import get_hashes, analyze_metadata, hex_tool
from modules.digital_forensics.steganography import encode_message, decode_message
from modules.digital_forensics.exif_extractor import extract_exif

# Tools
from modules.tools.metadata_analyzer import extract_metadata
from modules.tools.hex_tool import file_to_hex, hex_to_file

# Cryptography
from modules.cryptography.crypto_tool import custom_encrypt, custom_decrypt
from modules.cryptography.aes_tool import aes_encrypt, aes_decrypt

# -------------------- APP CONFIG --------------------
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 128 * 1024 * 1024  # 128 MB limit

UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# -------------------- HOME --------------------
@app.route('/')
def index():
    return render_template('index.html')

# -------------------- CTF MODULE --------------------
@app.route('/ctf')
def ctf_main():
    return render_template('ctf_helpers.html')

@app.route('/ctf/base-detector', methods=['POST'])
def base_detector():
    encoded_text = request.form.get('encoded_text', '')
    base_result = detect_base(encoded_text)
    return render_template('ctf_helpers.html', base_result=base_result, encoded_input=encoded_text)

@app.route('/ctf/decode', methods=['POST'])
def decode_route():
    input_text = request.form.get('input_text', '')
    encoding = request.form.get('encoding', '')
    result = decode_text(input_text, encoding)
    return render_template('ctf_helpers.html', decode_result=result, input_text=input_text, selected_encoding=encoding)

@app.route('/ctf/magic-decode', methods=['POST'])
def magic_decode():
    magic_input = request.form.get('magic_input', '')
    magic_results = magic_auto_decode(magic_input)
    return render_template('ctf_helpers.html', magic_input=magic_input, magic_results=magic_results, active_tab="magic")

@app.route('/ctf/caesar-crack', methods=['POST'])
def caesar_crack():
    input_text = request.form.get('caesar_input', '')
    cracked_results = caesar_brute_force(input_text)
    return render_template('ctf_helpers.html', caesar_crack_results=cracked_results, caesar_input=input_text)

@app.route('/ctf/hash-id', methods=['POST'])
def hash_identifier():
    hash_input = request.form.get("hash_input", "").strip()
    hash_types = identify_hash(hash_input)
    return render_template('ctf_helpers.html', hash_input=hash_input, hash_types=hash_types)



# -------------------- DIGITAL FORENSICS --------------------
@app.route('/forensics')
def forensics_main():
    return render_template('forensics.html')

@app.route('/forensics/hash', methods=['POST'])
def compute_hashes():
    uploaded_file = request.files['file']
    if uploaded_file:
        filepath = os.path.join(UPLOAD_FOLDER, uploaded_file.filename)
        uploaded_file.save(filepath)
        hashes = get_hashes(filepath)
        return render_template('forensics.html', hash_result=hashes)
    return redirect('/forensics')

@app.route('/forensics/meta-analyze', methods=['POST'])
def metadata_analyzer():
    uploaded_file = request.files['file']
    if uploaded_file:
        filepath = os.path.join(UPLOAD_FOLDER, uploaded_file.filename)
        uploaded_file.save(filepath)
        metadata, file_type = extract_metadata(filepath)
        return render_template('forensics.html', meta_result=metadata, file_type=file_type)
    return redirect('/forensics')

@app.route('/tools/exif/edit', methods=['POST'])
def edit_exif():
    image_file = request.files['image']
    if not image_file:
        return redirect('/tools')

    encoding_mode = request.form.get("encoding_mode", "clean")  # clean or garbage

    img = Image.open(image_file)
    exif_dict = {"0th": {}, "Exif": {}, "GPS": {}, "1st": {}, "thumbnail": None}
    form = request.form

    orientation_int = int(form.get("orientation", "1"))

    try:
        iso_value = int(form.get("iso", "100"))
    except ValueError:
        iso_value = 100

    gps_lat_ref = form.get("gps_lat", "").strip().upper()
    gps_lon_ref = form.get("gps_lon", "").strip().upper()

    def sanitize(val):
        if not val: return val
        if encoding_mode == "clean":
            return ''.join([c for c in val if 32 <= ord(c) <= 126])
        elif encoding_mode == "garbage":
            return ''.join([chr((ord(c) + 128) % 256) if c.isprintable() else '¤' for c in val])
        return val

    fields = {
        "0th": {
            piexif.ImageIFD.Artist: sanitize(form.get("author")),
            piexif.ImageIFD.Software: sanitize(form.get("software")),
            piexif.ImageIFD.ImageDescription: sanitize(form.get("description")),
            piexif.ImageIFD.Make: sanitize(form.get("make")),
            piexif.ImageIFD.Model: sanitize(form.get("model")),
            piexif.ImageIFD.DateTime: sanitize(form.get("datetime")),
            piexif.ImageIFD.Orientation: orientation_int
        },
        "Exif": {
            piexif.ExifIFD.ISOSpeedRatings: iso_value
        },
        "GPS": {
            piexif.GPSIFD.GPSLatitudeRef: gps_lat_ref[0].encode() if gps_lat_ref else b'N',
            piexif.GPSIFD.GPSLongitudeRef: gps_lon_ref[0].encode() if gps_lon_ref else b'E'
        }
    }

    for section, tag_dict in fields.items():
        for tag, value in tag_dict.items():
            if value:
                exif_dict[section][tag] = value.encode('utf-8', errors='ignore') if isinstance(value, str) else value

    exif_bytes = piexif.dump(exif_dict)
    img_bytes = io.BytesIO()
    img.save(img_bytes, format='JPEG', exif=exif_bytes)
    img_bytes.seek(0)

    return send_file(
        img_bytes,
        as_attachment=True,
        download_name="edited_image.jpg",
        mimetype='image/jpeg'
    )



# -------------------- STEGANOGRAPHY --------------------
@app.route('/tools/stego/encode', methods=['POST'])
def stego_encode():
    if 'image' not in request.files or 'message' not in request.form:
        return render_template('forensics.html', stego_result="❌ Invalid form data.")

    image = request.files['image']
    message = request.form['message']
    if not image or not message:
        return render_template('forensics.html', stego_result="❌ Image and message required.")

    input_path = os.path.join(UPLOAD_FOLDER, image.filename)
    output_path = os.path.join(UPLOAD_FOLDER, f"encoded_{image.filename}")
    image.save(input_path)

    encode_message(input_path, message, output_path)

    return render_template(
        'forensics.html',
        stego_result="✅ Message encoded successfully in image.",
        encoded_image=os.path.basename(output_path)
    )

@app.route('/tools/stego/decode', methods=['POST'])
def stego_decode():
    if 'image' not in request.files:
        return render_template('forensics.html', decode_result="❌ No image uploaded.")

    image = request.files['image']
    if image.filename == '':
        return render_template('forensics.html', decode_result="❌ No image selected.")

    input_path = os.path.join(UPLOAD_FOLDER, image.filename)
    image.save(input_path)

    hidden_message = decode_message(input_path)
    cleaned_message = hidden_message.strip()

    return render_template('forensics.html', decode_result=cleaned_message)

# -------------------- TOOLS MODULE --------------------
@app.route('/tools')
def tools_main():
    return render_template('tools.html')

@app.route('/tools/metadata', methods=['POST'])
def metadata_tools():
    uploaded_file = request.files['file']
    if uploaded_file:
        filepath = os.path.join(UPLOAD_FOLDER, uploaded_file.filename)
        uploaded_file.save(filepath)
        metadata, file_type = extract_metadata(filepath)
        return render_template('tools.html', metadata=metadata, file_type=file_type)
    return redirect('/tools')

@app.route('/tools/exif', methods=['POST'])
def exif_extractor():
    uploaded_file = request.files['image']
    if uploaded_file:
        filepath = os.path.join(UPLOAD_FOLDER, uploaded_file.filename)
        uploaded_file.save(filepath)
        exif_data = extract_exif(filepath)
        return render_template('forensics.html', exif_data=exif_data)
    return redirect('/forensics')

@app.route('/tools/hex-viewer', methods=['POST'])
def hex_viewer_tools():
    uploaded_file = request.files['file']
    if uploaded_file:
        filepath = os.path.join(UPLOAD_FOLDER, uploaded_file.filename)
        uploaded_file.save(filepath)
        hex_data = file_to_hex(filepath)
        return render_template('tools.html', hex_data=hex_data)
    return redirect('/tools')

@app.route('/tools/hex-to-image', methods=['POST'])
def hex_to_file_route():
    hex_file = request.files.get('hex_file')
    filetype = request.form.get('filetype', 'png')

    if hex_file:
        try:
            hex_data = hex_file.read().decode('utf-8')
            output_filename = f"converted_output.{filetype}"
            output_path = hex_to_file(hex_data, os.path.join(UPLOAD_FOLDER, output_filename))
            return render_template('tools.html', hex_image=output_filename)
        except Exception as e:
            return render_template('tools.html', error={"hex": str(e)})
    return render_template('tools.html', error={"hex": "No HEX file uploaded."})

# -------------------- CRYPTOGRAPHY --------------------
@app.route('/crypto')
def crypto_main():
    return render_template('cryptography.html', aes_data={}, active_tab='caesar')

@app.route('/crypto/encrypt', methods=['POST'])
def encrypt_text():
    plain_text = request.form.get('plain_text', '')
    key = request.form.get('key', '5')
    encrypted_text = custom_encrypt(plain_text, key)
    return render_template('cryptography.html', plain_text=plain_text, encrypted_text=encrypted_text, aes_data={}, active_tab='caesar')

@app.route('/crypto/decrypt', methods=['POST'])
def decrypt_text():
    cipher_text = request.form.get('cipher_text', '')
    key = request.form.get('key', '5')
    decrypted_text = custom_decrypt(cipher_text, key)
    return render_template('cryptography.html', cipher_text=cipher_text, decrypted_text=decrypted_text, aes_data={}, active_tab='caesar')

@app.route('/crypto/aes/encrypt', methods=['POST'])
def aes_encrypt_route():
    text = request.form.get('plain_text', '')
    key = request.form.get('key', '')
    try:
        result = aes_encrypt(text, key)
        return render_template(
            'cryptography.html',
            aes_plain_text=text,
            aes_encrypted=result,
            aes_data={},
            active_tab='aes'
        )
    except Exception as e:
        return render_template(
            'cryptography.html',
            aes_plain_text=text,
            aes_encrypted={"error": str(e)},
            aes_data={},
            active_tab='aes'
        )

@app.route('/crypto/aes/decrypt', methods=['POST'])
def aes_decrypt_route():
    ciphertext = request.form.get('ciphertext')
    nonce = request.form.get('nonce')
    tag = request.form.get('tag')
    key = request.form.get('key')
    aes_data = {"ciphertext": ciphertext, "nonce": nonce, "tag": tag}
    try:
        decrypted = aes_decrypt(ciphertext, nonce, tag, key)
        return render_template(
            'cryptography.html',
            aes_data=aes_data,
            aes_decrypted=decrypted,
            active_tab='aes'
        )
    except Exception as e:
        return render_template(
            'cryptography.html',
            aes_data=aes_data,
            aes_decrypted=f"❌ Error: {e}",
            active_tab='aes'
        )

# -------------------- FILES --------------------
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

# -------------------- ERROR HANDLING --------------------
@app.errorhandler(RequestEntityTooLarge)
def handle_large_file(e):
    return render_template('forensics.html', error={"hex": "⚠️ Uploaded data too large! Limit is 128MB."}), 413

# -------------------- RUN --------------------
if __name__ == "__main__":
    app.run(debug=True)
