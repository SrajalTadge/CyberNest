from flask import Flask, render_template, request
from modules import ctf_helpers, cryptography_tools, digital_forensics

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/ctf', methods=['GET', 'POST'])
def ctf():
    result = None
    if request.method == 'POST':
        text = request.form['text']
        base = request.form['base']
        result = ctf_helpers.convert_base(text, base)
    return render_template('ctf.html', result=result)

@app.route('/crypto', methods=['GET', 'POST'])
def crypto():
    result = None
    if request.method == 'POST':
        mode = request.form['mode']
        message = request.form['message']
        key = request.form['key']
        if mode == 'encrypt':
            result = cryptography_tools.aes_encrypt(message, key)
        else:
            result = cryptography_tools.aes_decrypt(message, key)
    return render_template('crypto.html', result=result)

@app.route('/forensics', methods=['GET', 'POST'])
def forensics():
    result = None
    if request.method == 'POST':
        file = request.files['file']
        result = digital_forensics.extract_metadata(file)
    return render_template('forensics.html', result=result)

if __name__ == '__main__':
    app.run(debug=True)
