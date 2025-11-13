from flask import Flask, request, make_response
import subprocess
import os
import pickle
app = Flask(__name__)
# Insecure Deserialization
@app.route('/unpickle', methods=['POST'])
def unpickle():
    data = request.data  # This could be user-controlled
    obj = pickle.loads(data)  # Insecure deserialization
    return "Object deserialized!"
# Command Injection
@app.route('/cmd')
def cmd():
    cmd = request.args.get("cmd")  # User-controlled input
    return subprocess.check_output(cmd, shell=True)  # Command injection
# Path Traversal
@app.route('/get-file')
def get_file():
    filename = request.args.get("filename")  # User input
    with open(filename, 'r') as f:  # Path traversal
        content = f.read()
    return content
# Incorrect Use of make_response() Leading to XSS
@app.route('/xss')
def xss():
    response = make_response("Hello, World!")
    response.headers['Content-Type'] = "application/javascript"  # Potential XSS
    return response
if __name__ == '__main__':
    app.run(debug=True)