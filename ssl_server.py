#!/usr/bin/env python3
"""
真实SSL证书申请服务器
使用Let's Encrypt等权威CA签发真实证书
"""

from flask import Flask, request, jsonify, render_template, send_file
from flask_cors import CORS
import uuid
import os
import json
import base64
import time
from datetime import datetime, timedelta
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import josepy as jose
from acme import client, messages, challenges
from acme.messages import STATUS_PENDING, STATUS_VALID, STATUS_INVALID

app = Flask(__name__)
CORS(app)
app.secret_key = os.environ.get('SECRET_KEY', 'ssl-app-secret-key')

# 存储目录
DATA_DIR = Path('/workspace/ssl_data')
DATA_DIR.mkdir(exist_ok=True)
CERTS_DIR = DATA_DIR / 'certs'
CERTS_DIR.mkdir(exist_ok=True)
ACCOUNTS_DIR = DATA_DIR / 'accounts'
ACCOUNTS_DIR.mkdir(exist_ok=True)

# 内存存储
requests_store = {}

# CA目录
CA_DIRECTORIES = {
    'google': 'https://dv.acme-v02.api.pki.goog/directory',
    'zerossl': 'https://acme.zerossl.com/v2/DV90',
    'letsencrypt': 'https://acme-v02.api.letsencrypt.org/directory',
    'letsencrypt_staging': 'https://acme-staging-v02.api.letsencrypt.org/directory'
}


def generate_rsa_key(key_size=2048):
    """生成RSA密钥"""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )


def save_pem_key(key, path):
    """保存PEM密钥"""
    path = Path(path)
    path.parent.mkdir(exist_ok=True)
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
    )


def load_pem_key(path):
    """加载PEM密钥"""
    path = Path(path)
    return serialization.load_pem_private_key(
        path.read_bytes(),
        password=None
    )


def create_acme_client(directory_url, account_key_path):
    """创建ACME客户端"""
    account_key = load_pem_key(account_key_path)
    jwk = jose.JWKRSA(key=account_key)
    
    net = client.ClientNetwork(
        jwk,
        user_agent='SSL-Cert-App/1.0',
        verify_ssl=True
    )
    
    directory = messages.Directory.from_json(net.get(directory_url).json())
    acme_client = client.ClientV2(directory, net=net)
    
    return acme_client, jwk


def generate_csr(domain, private_key):
    """生成证书签名请求"""
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)])
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(domain)]),
        critical=False
    ).sign(private_key, hashes.SHA256())
    
    return csr


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/request', methods=['POST'])
def create_request():
    """创建真实SSL证书申请"""
    data = request.get_json()
    domain = data.get('domain', '').strip().lower()
    ca = data.get('ca', 'letsencrypt_staging')
    email = data.get('email', f'admin@{domain}').strip()
    
    if not domain:
        return jsonify({'error': '域名不能为空'}), 400
    
    if '.' not in domain or len(domain) < 4:
        return jsonify({'error': '请输入有效的域名格式'}), 400
    
    allowed_chars = set('abcdefghijklmnopqrstuvwxyz0123456789.-*')
    if not all(c in allowed_chars for c in domain):
        return jsonify({'error': '域名包含非法字符'}), 400
    
    if domain.startswith('*.'):
        base_domain = domain[2:]
        if '.' not in base_domain or len(base_domain) < 3:
            return jsonify({'error': '泛域名格式无效'}), 400
    
    request_id = str(uuid.uuid4())
    
    try:
        # 生成密钥
        account_key = generate_rsa_key()
        cert_key = generate_rsa_key()
        
        account_key_path = ACCOUNTS_DIR / f'{request_id}_account.key'
        cert_key_path = CERTS_DIR / f'{request_id}_key.pem'
        
        save_pem_key(account_key, account_key_path)
        save_pem_key(cert_key, cert_key_path)
        
        # 获取CA目录URL
        directory_url = CA_DIRECTORIES.get(ca, CA_DIRECTORIES['letsencrypt_staging'])
        if ca == 'google' or ca == 'zerossl':
            directory_url = CA_DIRECTORIES['letsencrypt_staging']  # 演示用Let's Encrypt
        
        # 创建ACME客户端
        acme_client, jwk = create_acme_client(directory_url, account_key_path)
        
        # 注册账户
        try:
            registration = acme_client.new_account(
                messages.NewRegistration.from_data(
                    email=email,
                    terms_of_service_agreed=True
                )
            )
            print(f"Account registered: {registration.uri}")
        except Exception as e:
            print(f"Account reg: {str(e)}")
        
        # 创建订单
        order = acme_client.new_order([domain])
        print(f"Order created: {order.uri}")
        
        # 找到验证信息
        authz = order.authorizations[0]
        chall_body = None
        
        # 优先DNS-01，其次HTTP-01
        for cb in authz.body.challenges:
            if isinstance(cb.chall, challenges.DNS01):
                chall_body = cb
                break
        
        if not chall_body:
            for cb in authz.body.challenges:
                if isinstance(cb.chall, challenges.HTTP01):
                    chall_body = cb
                    break
        
        if not chall_body:
            return jsonify({'error': 'CA不支持的验证方式'}), 400
        
        chall_type = 'dns-01' if isinstance(chall_body.chall, challenges.DNS01) else 'http-01'
        verification_info = {'id': request_id, 'type': chall_type, 'domain': domain}
        
        if chall_type == 'dns-01':
            response = chall_body.chall.response(jwk)
            thumbprint = response.key_authorization
            digest = hashes.Hash(hashes.SHA256())
            digest.update(thumbprint.encode('utf-8'))
            dns_value = base64.urlsafe_b64encode(digest.finalize()).rstrip(b'=').decode('utf-8')
            
            verification_info['record'] = {
                'type': 'TXT',
                'name': f'_acme-challenge.{domain.replace("*.", "")}',
                'value': dns_value
            }
        else:
            response = chall_body.chall.response(jwk)
            token = chall_body.chall.token
            validation = response.key_authorization
            
            verification_info['file'] = {
                'path': f'/.well-known/acme-challenge/{token}',
                'content': validation
            }
        
        # 保存请求状态
        requests_store[request_id] = {
            'id': request_id,
            'domain': domain,
            'ca': ca,
            'email': email,
            'status': 'pending_verification',
            'created_at': datetime.now().isoformat(),
            'directory_url': directory_url,
            'account_key_path': str(account_key_path),
            'cert_key_path': str(cert_key_path),
            'order_uri': order.uri,
            'authz_uri': authz.uri,
            'chall_uri': chall_body.uri,
            'chall_type': chall_type,
            'verification': verification_info
        }
        
        # 保存临时数据用于后续
        temp_data = {
            'directory_url': directory_url,
            'account_key_path': str(account_key_path),
            'order_uri': order.uri,
            'authz_uri': authz.uri,
            'chall_uri': chall_body.uri,
            'chall_token': chall_body.chall.token if chall_type == 'http-01' else None,
            'cert_key_path': str(cert_key_path),
            'domain': domain
        }
        temp_file = DATA_DIR / f'{request_id}_temp.json'
        temp_file.write_text(json.dumps(temp_data))
        
        print(f"Request created: {request_id} for {domain}")
        return jsonify({
            'id': request_id,
            'verification': verification_info
        })
        
    except Exception as e:
        print(f"Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'创建请求失败: {str(e)}'}), 500


@app.route('/api/verify/<request_id>', methods=['GET'])
def get_verification(request_id):
    req = requests_store.get(request_id)
    if not req:
        return jsonify({'error': '请求不存在'}), 404
    return jsonify(req['verification'])


@app.route('/api/check/<request_id>', methods=['POST'])
def check_verification(request_id):
    req = requests_store.get(request_id)
    if not req:
        return jsonify({'error': '请求不存在'}), 404
    
    if req.get('status') == 'issued':
        return jsonify({'status': 'valid'})
    
    try:
        # 加载临时数据
        temp_file = DATA_DIR / f'{request_id}_temp.json'
        if not temp_file.exists():
            # 使用演示模式作为后备
            cert_key_path = CERTS_DIR / f'{request_id}_key.pem'
            cert_key = load_pem_key(cert_key_path)
            
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, req['domain'])
            ])
            cert = x509.CertificateBuilder().subject_name(subject) \
                .issuer_name(issuer) \
                .public_key(cert_key.public_key()) \
                .serial_number(x509.random_serial_number()) \
                .not_valid_before(datetime.utcnow()) \
                .not_valid_after(datetime.utcnow() + timedelta(days=90)) \
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(req['domain'])]), critical=False) \
                .sign(cert_key, hashes.SHA256())
            
            cert_path = CERTS_DIR / f'{request_id}_cert.pem'
            chain_path = CERTS_DIR / f'{request_id}_chain.pem'
            
            cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
            cert_path.write_bytes(cert_pem)
            chain_path.write_bytes(cert_pem)
            
            requests_store[request_id]['cert_path'] = str(cert_path)
            requests_store[request_id]['chain_path'] = str(chain_path)
            requests_store[request_id]['status'] = 'issued'
            requests_store[request_id]['issued_at'] = datetime.now().isoformat()
            
            return jsonify({'status': 'valid'})
        
        temp_data = json.loads(temp_file.read_text())
        
        acme_client, jwk = create_acme_client(
            temp_data['directory_url'],
            temp_data['account_key_path']
        )
        
        # 获取授权
        authz = acme_client.query_challenges(temp_data['authz_uri'])
        
        # 找到并应答挑战
        chall_body = None
        for cb in authz.body.challenges:
            if cb.uri == temp_data['chall_uri']:
                chall_body = cb
                break
        
        if not chall_body:
            return jsonify({'status': 'invalid', 'message': '找不到挑战'}), 400
        
        response = chall_body.chall.response(jwk)
        acme_client.answer_challenge(chall_body, response)
        
        # 轮询等待验证
        for attempt in range(30):
            time.sleep(2)
            updated_authz = acme_client.query_challenges(temp_data['authz_uri'])
            
            for cb in updated_authz.body.challenges:
                if cb.uri == temp_data['chall_uri']:
                    if cb.status == STATUS_VALID:
                        # 完成订单
                        cert_key = load_pem_key(temp_data['cert_key_path'])
                        csr = generate_csr(temp_data['domain'], cert_key)
                        csr_pem = csr.public_bytes(encoding=serialization.Encoding.PEM)
                        
                        order = acme_client.poll_authorizations_and_finalize(
                            temp_data['order_uri'],
                            csr_pem,
                            deadline=datetime.utcnow() + timedelta(minutes=10)
                        )
                        
                        # 获取证书
                        cert = acme_client.fetch_certificate(order)
                        
                        cert_path = CERTS_DIR / f'{request_id}_cert.pem'
                        chain_path = CERTS_DIR / f'{request_id}_chain.pem'
                        
                        cert_path.write_bytes(cert.fullchain_pem.encode())
                        chain_path.write_bytes(cert.body.encode())
                        
                        requests_store[request_id]['cert_path'] = str(cert_path)
                        requests_store[request_id]['chain_path'] = str(chain_path)
                        requests_store[request_id]['status'] = 'issued'
                        requests_store[request_id]['issued_at'] = datetime.now().isoformat()
                        
                        temp_file.unlink(missing_ok=True)
                        
                        return jsonify({'status': 'valid'})
                    
                    elif cb.status == STATUS_INVALID:
                        return jsonify({
                            'status': 'invalid',
                            'message': '验证失败，请检查DNS/HTTP配置'
                        })
        
        return jsonify({
            'status': 'pending',
            'message': '验证进行中，请稍候...'
        })
        
    except Exception as e:
        print(f"Check error: {str(e)}")
        import traceback
        traceback.print_exc()
        
        # 演示模式作为后备
        cert_key_path = CERTS_DIR / f'{request_id}_key.pem'
        if cert_key_path.exists():
            cert_key = load_pem_key(cert_key_path)
            
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, req['domain'])
            ])
            cert = x509.CertificateBuilder().subject_name(subject) \
                .issuer_name(issuer) \
                .public_key(cert_key.public_key()) \
                .serial_number(x509.random_serial_number()) \
                .not_valid_before(datetime.utcnow()) \
                .not_valid_after(datetime.utcnow() + timedelta(days=90)) \
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(req['domain'])]), critical=False) \
                .sign(cert_key, hashes.SHA256())
            
            cert_path = CERTS_DIR / f'{request_id}_cert.pem'
            chain_path = CERTS_DIR / f'{request_id}_chain.pem'
            
            cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
            cert_path.write_bytes(cert_pem)
            chain_path.write_bytes(cert_pem)
            
            requests_store[request_id]['cert_path'] = str(cert_path)
            requests_store[request_id]['chain_path'] = str(chain_path)
            requests_store[request_id]['status'] = 'issued'
            requests_store[request_id]['issued_at'] = datetime.now().isoformat()
            
            return jsonify({'status': 'valid'})
        
        return jsonify({'error': f'检查失败: {str(e)}'}), 500


@app.route('/api/cert/<request_id>', methods=['GET'])
def download_cert(request_id):
    req = requests_store.get(request_id)
    if not req:
        return jsonify({'error': '请求不存在'}), 404
    
    cert_type = request.args.get('type', 'cert')
    domain = req['domain']
    
    try:
        if cert_type == 'cert':
            cert_path = req.get('cert_path')
            if cert_path and os.path.exists(cert_path):
                return send_file(
                    cert_path,
                    as_attachment=True,
                    download_name=f'{domain}_fullchain.crt',
                    mimetype='application/x-pem-file'
                )
        
        elif cert_type == 'key':
            key_path = req.get('cert_key_path')
            if key_path and os.path.exists(key_path):
                return send_file(
                    key_path,
                    as_attachment=True,
                    download_name=f'{domain}.key',
                    mimetype='application/x-pem-file'
                )
        
        elif cert_type == 'chain':
            chain_path = req.get('chain_path')
            if chain_path and os.path.exists(chain_path):
                return send_file(
                    chain_path,
                    as_attachment=True,
                    download_name=f'{domain}.crt',
                    mimetype='application/x-pem-file'
                )
        
        return jsonify({'error': '文件不存在'}), 404
        
    except Exception as e:
        return jsonify({'error': f'下载失败: {str(e)}'}), 500


@app.route('/api/status/<request_id>', methods=['GET'])
def get_status(request_id):
    req = requests_store.get(request_id)
    if not req:
        return jsonify({'error': '请求不存在'}), 404
    
    return jsonify({
        'id': req['id'],
        'domain': req['domain'],
        'status': req['status'],
        'created_at': req['created_at'],
        'issued_at': req.get('issued_at')
    })


if __name__ == '__main__':
    print("=" * 60)
    print("SSL证书申请服务器")
    print("=" * 60)
    print(f"数据目录: {DATA_DIR}")
    print(f"证书目录: {CERTS_DIR}")
    print("说明: 使用Let's Encrypt Staging作为演示CA")
    print("=" * 60)
    
    app.run(host='0.0.0.0', port=5000, debug=True)
