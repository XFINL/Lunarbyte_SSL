
from flask import Flask, request, jsonify, render_template, send_file
from flask_cors import CORS
import uuid
import os
from datetime import datetime
import tempfile

app = Flask(__name__)
CORS(app)
app.secret_key = os.environ.get('SECRET_KEY', 'demo-secret-key')

requests_store = {}
TEMP_DIR = tempfile.mkdtemp()


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/request', methods=['POST'])
def create_request():
    data = request.get_json()
    domain = data.get('domain')
    ca = data.get('ca', 'letsencrypt_staging')
    email = data.get('email', f'admin@{domain}')
    
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400
    
    request_id = str(uuid.uuid4())
    
    verification_info = {
        'id': request_id,
        'type': 'dns-01',
        'domain': domain,
        'record': {
            'type': 'TXT',
            'name': f'_acme-challenge.{domain}',
            'value': f'demo-validation-{uuid.uuid4().hex[:16]}'
        }
    }
    
    requests_store[request_id] = {
        'id': request_id,
        'domain': domain,
        'ca': ca,
        'email': email,
        'status': 'pending_verification',
        'created_at': datetime.now().isoformat(),
        'verification': verification_info
    }
    
    cert_path = os.path.join(TEMP_DIR, f'{request_id}_cert.pem')
    key_path = os.path.join(TEMP_DIR, f'{request_id}_key.pem')
    
    with open(cert_path, 'w') as f:
        f.write(f"""-----BEGIN CERTIFICATE-----
MIIC5zCCAc+gAwIBAIUR7n9xQ3X7vQ8K5w3n9xQ3X7vQ8wDQYJKoZIhvcNAQELBQAw
ADAeFw0yNDAxMDExMjAwMDBaFw0yNDA0MDExMjAwMDBaMAAwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQD... (Demo Certificate for {domain})
-----END CERTIFICATE-----""")
    
    with open(key_path, 'w') as f:
        f.write(f"""-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQD... (Demo Key)
-----END PRIVATE KEY-----""")
    
    requests_store[request_id]['cert_path'] = cert_path
    requests_store[request_id]['key_path'] = key_path
    
    return jsonify({
        'id': request_id,
        'verification': verification_info
    })


@app.route('/api/verify/<request_id>', methods=['GET'])
def get_verification(request_id):
    req = requests_store.get(request_id)
    if not req:
        return jsonify({'error': 'Request not found'}), 404
    
    return jsonify(req['verification'])


@app.route('/api/check/<request_id>', methods=['POST'])
def check_verification(request_id):
    req = requests_store.get(request_id)
    if not req:
        return jsonify({'error': 'Request not found'}), 404
    
    requests_store[request_id]['status'] = 'issued'
    
    return jsonify({'status': 'valid'})


@app.route('/api/cert/<request_id>', methods=['GET'])
def download_cert(request_id):
    req = requests_store.get(request_id)
    if not req:
        return jsonify({'error': 'Request not found'}), 404
    
    cert_type = request.args.get('type', 'cert')
    
    if cert_type == 'cert':
        return send_file(req['cert_path'], as_attachment=True, download_name=f'{req["domain"]}.crt')
    elif cert_type == 'key':
        return send_file(req['key_path'], as_attachment=True, download_name=f'{req["domain"]}.key')
    elif cert_type == 'chain':
        return send_file(req['cert_path'], as_attachment=True, download_name=f'{req["domain"]}_chain.crt')
    
    return jsonify({'error': 'Invalid type'}), 400


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
