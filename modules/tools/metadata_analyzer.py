from PyPDF2 import PdfReader
from docx import Document
from PIL import Image
from PIL.ExifTags import TAGS

def extract_metadata(file_path):
    metadata = {}
    file_type = "unknown"

    try:
        # For PDF files
        if file_path.lower().endswith('.pdf'):
            file_type = "pdf"
            reader = PdfReader(file_path)
            metadata = {k: str(v) for k, v in reader.metadata.items()}

        # For DOCX files
        elif file_path.lower().endswith('.docx'):
            file_type = "docx"
            doc = Document(file_path)
            props = doc.core_properties
            metadata = {
                'author': props.author,
                'title': props.title,
                'subject': props.subject,
                'created': str(props.created),
                'modified': str(props.modified)
            }

        # For Image files
        elif file_path.lower().endswith(('.jpg', '.jpeg', '.png')):
            file_type = "image"
            image = Image.open(file_path)
            metadata['format'] = image.format
            metadata['mode'] = image.mode
            metadata['size'] = image.size

            # Extract EXIF if present
            exif_data = image.getexif()
            if exif_data:
                for tag_id, value in exif_data.items():
                    tag = TAGS.get(tag_id, tag_id)
                    metadata[f"EXIF_{tag}"] = str(value)

    except Exception as e:
        metadata["error"] = str(e)

    return metadata if metadata else {"info": "No metadata found"}, file_type
