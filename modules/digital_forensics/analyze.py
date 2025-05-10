# modules/digital_forensics/analyze.py

import hashlib
from PyPDF2 import PdfReader
from docx import Document
from PIL import Image
from PIL.ExifTags import TAGS

# 🔐 Hash computation
def get_hashes(file_path):
    hashes = {
        'md5': hashlib.md5(),
        'sha1': hashlib.sha1(),
        'sha256': hashlib.sha256()
    }
    with open(file_path, 'rb') as f:
        data = f.read()
        for algo in hashes.values():
            algo.update(data)
    return {k: v.hexdigest() for k, v in hashes.items()}

# 🧪 HEX Tool (Viewer and Converter)
def hex_tool(file_path=None, hex_data=None, to_file=False, extension='png'):
    if to_file:
        # Convert HEX to file
        hex_data = hex_data.replace('\n', '').replace(' ', '').strip()
        if len(hex_data) % 2 != 0:
            raise ValueError("HEX length is not even. Invalid data.")
        try:
            binary_data = bytes.fromhex(hex_data)
            filename = f'converted_from_hex.{extension}'
            output_path = f'uploads/{filename}'
            with open(output_path, 'wb') as f:
                f.write(binary_data)
            return output_path
        except ValueError:
            raise ValueError("Invalid HEX data. Cannot convert to file.")
    else:
        # Convert file to HEX
        with open(file_path, 'rb') as f:
            return f.read().hex()

# 📁 Metadata Analyzer
def analyze_metadata(file_path):
    result = {}
    if file_path.lower().endswith('.pdf'):
        reader = PdfReader(file_path)
        result = {k: str(v) for k, v in reader.metadata.items()}
    elif file_path.lower().endswith('.docx'):
        doc = Document(file_path)
        props = doc.core_properties
        result = {
            'author': props.author,
            'title': props.title,
            'subject': props.subject,
            'created': str(props.created),
            'modified': str(props.modified)
        }
    elif file_path.lower().endswith(('.jpg', '.jpeg', '.png')):
        image = Image.open(file_path)
        info = image._getexif()
        if info:
            for tag, val in info.items():
                name = TAGS.get(tag, tag)
                result[name] = str(val)
    else:
        result = {"Info": "Unsupported file type"}
    return result
