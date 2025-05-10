# modules/digital_forensics/exif_extractor.py

from PIL import Image
from PIL.ExifTags import TAGS

def extract_exif(file_path):
    img = Image.open(file_path)
    exif_data = img._getexif()
    exif_metadata = {}

    if exif_data:
        for tag, value in exif_data.items():
            tag_name = TAGS.get(tag, tag)
            exif_metadata[tag_name] = value
    return exif_metadata
