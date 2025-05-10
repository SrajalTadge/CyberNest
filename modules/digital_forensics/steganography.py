# modules/digital_forensics/steganography.py

from PIL import Image

EOF_MARKER = "|||END|||"

def encode_message(image_path, message, output_path):
    img = Image.open(image_path)
    binary_msg = ''.join(format(ord(c), '08b') for c in (message + EOF_MARKER))

    pixels = list(img.getdata())
    new_pixels = []
    data_index = 0

    for pixel in pixels:
        r, g, b = pixel[:3]
        new_rgb = []
        for color in (r, g, b):
            if data_index < len(binary_msg):
                new_rgb.append((color & ~1) | int(binary_msg[data_index]))
                data_index += 1
            else:
                new_rgb.append(color)
        new_pixels.append(tuple(new_rgb))

    img.putdata(new_pixels)
    img.save(output_path)
    return output_path

def decode_message(image_path):
    img = Image.open(image_path)
    pixels = list(img.getdata())
    bits = ''

    for pixel in pixels:
        for color in pixel[:3]:
            bits += str(color & 1)

    chars = [chr(int(bits[i:i+8], 2)) for i in range(0, len(bits), 8)]
    message = ''.join(chars)

    if EOF_MARKER in message:
        return message.split(EOF_MARKER)[0]
    return "❌ No hidden message found."
