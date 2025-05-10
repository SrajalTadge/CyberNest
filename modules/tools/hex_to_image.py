# modules/tools/hex_to_image.py

from PIL import Image
import io

def hex_to_image(hex_data, extension='png'):
    # Convert hex to bytes
    hex_data = hex_data.replace(' ', '').replace('\n', '')
    binary_data = bytes.fromhex(hex_data)

    # Create image from binary data
    image = Image.open(io.BytesIO(binary_data))
    output_path = f'uploads/converted_image.{extension}'
    image.save(output_path)
    return output_path
