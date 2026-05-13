
from flask import Flask, request, jsonify, render_template, send_file
from flask_cors import CORS
import uuid
import os
import json
from datetime import datetime
import tempfile
from acme import client, messages, challenges
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import josepy as jose

app = Flask(__name__)
CORS(app)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

# Temporary storage - in production use a database
requests_store = {}

# Directory for temp files
TEMP_DIR = tempfile.mkdtemp()

CA_DIRECTORY_URLS = {
    'letsencrypt': 'https://acme-v02.api.letsencrypt.org/directory',
    'letsencrypt_staging': 'https://acme-staging-v02.api.letsencrypt.org/directory',
    'zerossl': 'https://acme.zerossl.com/v2/DV90'
}


def generate_rsa_key(key_size=2048):
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    return key


def create_acme_client(ca_name, email):
    directory_url = CA_DIRECTORY_URLS.get(ca_name, CA_DIRECTORY_URLS['letsencrypt_staging'])
    
    # Generate account key
    account_key = generate_rsa_key()
    
    # Create ACME client
    net = client.ClientNetwork(account_key, user_agent='SSL-App/1.0')
    directory = messages.Directory.from_json(net.get(directory_url).json())
    acme_client = client.ClientV2(directory, net=net)
    
    # Register account
    registration = acme_client.new_account(
        messages.NewRegistration.from_data(email=email, terms_of_service_agreed=True)
    )
    
    return acme_client, account_key


def generate_csr(domain, private_key):
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, domain),
        ])
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(domain)]),
        critical=False,
    ).sign(private_key, hashes.SHA256())
    
    return csr


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
    
    try:
        # Generate keys
        account_key = generate_rsa_key()
        cert_key = generate_rsa_key()
        
        # Create ACME client
        directory_url = CA_DIRECTORY_URLS.get(ca, CA_DIRECTORY_URLS['letsencrypt_staging'])
        net = client.ClientNetwork(account_key, user_agent='SSL-App/1.0')
        directory = messages.Directory.from_json(net.get(directory_url).json())
        acme_client = client.ClientV2(directory, net=net)
        
        # Register account
        registration = acme_client.new_account(
            messages.NewRegistration.from_data(email=email, terms_of_service_agreed=True)
        )
        
        # Create order
        order = acme_client.new_order(domain)
        
        # Get challenges
        authzr = order.authorizations[0]
        challenge = None
        
        # Find HTTP-01 or DNS-01 challenge
        for chall_body in authzr.body.challenges:
            if isinstance(chall_body.chall, challenges.HTTP01):
                challenge = chall_body
                challenge_type = 'http-01'
                break
        else:
            for chall_body in authzr.body.challenges:
                if isinstance(chall_body.chall, challenges.DNS01):
                    challenge = chall_body
                    challenge_type = 'dns-01'
                    break
        
        if not challenge:
            return jsonify({'error': 'No supported challenge found'}), 400
        
        # Prepare verification info
        verification_info = {
            'id': request_id,
            'type': challenge_type,
            'domain': domain
        }
        
        if challenge_type == 'http-01':
            response = challenge.chall.response(account_key)
            verification_info['file'] = {
                'path': f'/.well-known/acme-challenge/{challenge.chall.token}',
                'content': response.to_part().decode('utf-8')
            }
        elif challenge_type == 'dns-01':
            response = challenge.chall.response(account_key)
            verification_info['record'] = {
                'type': 'TXT',
                'name': f'_acme-challenge.{domain}',
                'value': response.validation_for_owner(account_key)
            }
        
        # Save to store
        requests_store[request_id] = {
            'id': request_id,
            'domain': domain,
            'ca': ca,
            'email': email,
            'status': 'pending_verification',
            'created_at': datetime.now().isoformat(),
            'acme_client': acme_client,
            'account_key': account_key,
            'cert_key': cert_key,
            'order': order,
            'challenge': challenge,
            'verification': verification_info
        }
        
        return jsonify({
            'id': request_id,
            'verification': verification_info
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


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
    
    try:
        acme_client = req['acme_client']
        challenge = req['challenge']
        
        # Answer challenge
        response = challenge.chall.response(req['account_key'])
        acme_client.answer_challenge(challenge, response)
        
        # Poll for authorization
        orderr = acme_client.poll_authorizations(req['order'], wait=30)
        
        # Check if challenge is valid
        authzr = orderr.authorizations[0]
        chall_body = None
        for c in authzr.body.challenges:
            if c.uri == challenge.uri:
                chall_body = c
                break
        
        if chall_body and chall_body.status == messages.STATUS_VALID:
            # Challenge valid, finalize order
            csr = generate_csr(req['domain'], req['cert_key'])
            csr_pem = csr.public_bytes(encoding=serialization.Encoding.PEM)
            
            orderr = acme_client.finalize_order(req['order'], csr_pem)
            
            # Get certificate
            certificate_pem = acme_client.download_certificate(orderr)
            
            # Save certificate
            cert_path = os.path.join(TEMP_DIR, f'{request_id}_cert.pem')
            key_path = os.path.join(TEMP_DIR, f'{request_id}_key.pem')
            
            with open(cert_path, 'wb') as f:
                f.write(certificate_pem)
            
            with open(key_path, 'wb') as f:
                f.write(
                    req['cert_key'].private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=serialization.NoEncryption()
                    )
                )
            
            requests_store[request_id]['cert_path'] = cert_path
            requests_store[request_id]['key_path'] = key_path
            requests_store[request_id]['status'] = 'issued'
            
            return jsonify({'status': 'valid'})
        
        elif chall_body and chall_body.status == messages.STATUS_INVALID:
            return jsonify({
                'status': 'invalid',
                'message': 'Challenge verification failed. Please check your records.'
            })
        
        return jsonify({'status': 'pending'})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/cert/<request_id>', methods=['GET'])
def download_cert(request_id):
    req = requests_store.get(request_id)
    if not req:
        return jsonify({'error': 'Request not found'}), 404
    
    if req.get('status') != 'issued':
        return jsonify({'error': 'Certificate not yet issued'}), 400
    
    cert_type = request.args.get('type', 'cert')
    
    if cert_type == 'cert':
        return send_file(req['cert_path'], as_attachment=True, download_name=f'{req["domain"]}.crt')
    elif cert_type == 'key':
        return send_file(req['key_path'], as_attachment=True, download_name=f'{req["domain"]}.key')
    elif cert_type == 'chain':
        # For chain, we just send the same cert (for simplicity - in real world extract CA chain)
        return send_file(req['cert_path'], as_attachment=True, download_name=f'{req["domain"]}_chain.crt')
    
    return jsonify({'error': 'Invalid type'}), 400


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
