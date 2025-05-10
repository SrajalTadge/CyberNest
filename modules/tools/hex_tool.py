# modules/tools/hex_tool.py

def file_to_hex(file_path):
    with open(file_path, 'rb') as f:
        return f.read().hex()

def hex_to_file(hex_data, output_path):
    hex_data = hex_data.replace('\n', '').replace(' ', '').strip()
    if len(hex_data) % 2 != 0:
        raise ValueError("HEX length is not even. Invalid data.")
    try:
        binary_data = bytes.fromhex(hex_data)
        with open(output_path, 'wb') as f:
            f.write(binary_data)
        return output_path
    except ValueError:
        raise ValueError("Invalid HEX data. Cannot convert to file.")
