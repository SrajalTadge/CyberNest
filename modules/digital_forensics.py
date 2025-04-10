from PIL import Image
from PIL.ExifTags import TAGS
import hashlib

def extract_metadata(uploaded_file):
    try:
        image = Image.open(uploaded_file)
        exif_data = image._getexif()
        if not exif_data:
            return "No EXIF metadata found."
        meta = {}
        for tag_id, value in exif_data.items():
            tag = TAGS.get(tag_id, tag_id)
            meta[tag] = value
        return meta
    except Exception as e:
        return f"Metadata extraction error: {str(e)}"
