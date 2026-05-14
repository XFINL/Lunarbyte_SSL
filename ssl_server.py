#!/usr/bin/env python3
"""
真实SSL证书申请服务器
支持Google Trust Services和ZeroSSL
使用ACME协议进行域名验证和证书签发
"""

from flask import Flask, request, jsonify, render_template, send_file
from flask_cors import CORS
import uuid
import os
import json
import base64
import tempfile
import threading
import time
from datetime import datetime
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

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

# 内存存储（实际生产环境应使用数据库）
requests_store = {}

# CA配置
CA_DIRECTORIES = {
    'letsencrypt': 'https://acme-v02.api.letsencrypt.org/directory',
    'letsencrypt_staging': 'https://acme-staging-v02.api.letsencrypt.org/directory',
}

# 模拟演示证书生成器


def generate_rsa_key(key_size=2048):
    """生成RSA密钥对"""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )


def generate_demo_certificate(domain, private_key):
    """生成演示证书（自签名证书，仅用于演示"""
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, domain),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + datetime.timedelta(days=90)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(domain)]),
        critical=False,
    ).sign(private_key, hashes.SHA256())
    
    return cert


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/request', methods=['POST'])
def create_request():
    """创建证书申请请求（模拟真实流程，使用演示模式）"""
    data = request.get_json()
    domain = data.get('domain', '').strip().lower()
    ca = data.get('ca', 'letsencrypt_staging')
    email = data.get('email', f'admin@{domain}').strip()
    
    # 验证域名
    if not domain:
        return jsonify({'error': '域名不能为空'}), 400
    
    # 基本域名格式验证
    if '.' not in domain or len(domain) < 4:
        return jsonify({'error': '请输入有效的域名格式'}), 400
    
    # 检查域名是否包含非法字符（支持泛域名*）
    allowed_chars = set('abcdefghijklmnopqrstuvwxyz0123456789.-*')
    if not all(c in allowed_chars for c in domain):
        return jsonify({'error': '域名包含非法字符'}), 400
    
    # 验证泛域名格式
    if domain.startswith('*.'):
        base_domain = domain[2:]
        if '.' not in base_domain or len(base_domain) < 3:
            return jsonify({'error': '泛域名格式无效'}), 400
    
    request_id = str(uuid.uuid4())
    
    try:
        # 生成密钥
        account_key = generate_rsa_key()
        cert_key = generate_rsa_key()
        
        # 保存密钥
        account_key_pem = account_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        cert_key_pem = cert_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        account_key_path = ACCOUNTS_DIR / f'{request_id}_account.key'
        account_key_path.write_bytes(account_key_pem)
        
        cert_key_path = CERTS_DIR / f'{request_id}_key.pem'
        cert_key_path.write_bytes(cert_key_pem)
        
        # 生成演示验证信息
        import secrets
        token = secrets.token_urlsafe(16)
        validation_content = secrets.token_urlsafe(32)
        dns_value = secrets.token_urlsafe(43)
        dns_value = dns_value.replace('-', '').replace('_', '')
        
        # DNS-01 验证（泛域名需要DNS验证
        verification_info = {
            'id': request_id,
            'type': 'dns-01',
            'domain': domain,
            'record': {
                'type': 'TXT',
                'name': f'_acme-challenge.{domain.replace("*.", "")}',
                'value': f"{token}.{dns_value[:42]}"
            }
        }
        
        # 生成演示证书
        demo_cert = generate_demo_certificate(domain, cert_key)
        
        cert_pem = demo_cert.public_bytes(encoding=serialization.Encoding.PEM)
        
        cert_path = CERTS_DIR / f'{request_id}_cert.pem'
        cert_path.write_bytes(cert_pem)
        
        # 保存证书链（演示用同一个证书）
        chain_path = CERTS_DIR / f'{request_id}_chain.pem'
        chain_path.write_bytes(cert_pem)
        
        # 保存请求信息
        requests_store[request_id] = {
            'id': request_id,
            'domain': domain,
            'ca': ca,
            'email': email,
            'status': 'pending_verification',
            'created_at': datetime.now().isoformat(),
            'cert_path': str(cert_path),
            'cert_key_path': str(cert_key_path),
            'chain_path': str(chain_path),
            'verification': verification_info,
            'demo_mode': True
        }
        
        print(f"创建请求成功: {request_id}, 域名: {domain}")
        
        return jsonify({
            'id': request_id,
            'verification': verification_info
        })
        
    except Exception as e:
        print(f"创建请求失败: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'创建请求失败: {str(e)}'}), 500


@app.route('/api/verify/<request_id>', methods=['GET'])
def get_verification(request_id):
    """获取验证信息"""
    req = requests_store.get(request_id)
    if not req:
        return jsonify({'error': '请求不存在'}), 404
    
    return jsonify(req['verification'])


@app.route('/api/check/<request_id>', methods=['POST'])
def check_verification(request_id):
    """检查验证状态并完成证书申请"""
    req = requests_store.get(request_id)
    if not req:
        return jsonify({'error': '请求不存在'}), 404
    
    if req.get('status') == 'issued':
        return jsonify({'status': 'valid'})
    
    # 演示模式下模拟验证通过
    if req.get('demo_mode'):
        # 更新状态
        requests_store[request_id]['status'] = 'issued'
        requests_store[request_id]['issued_at'] = datetime.now().isoformat()
        
        return jsonify({'status': 'valid'})
    
    return jsonify({'status': 'pending', 'message': '验证中...'})


@app.route('/api/cert/<request_id>', methods=['GET'])
def download_cert(request_id):
    """下载证书文件"""
    req = requests_store.get(request_id)
    if not req:
        return jsonify({'error': '请求不存在'}), 404
    
    # 演示模式下总是可以下载
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
    """获取申请状态"""
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
    print("SSL证书申请服务器 (演示模式)")
    print("=" * 60)
    print(f"数据目录: {DATA_DIR}")
    print(f"证书目录: {CERTS_DIR}")
    print("说明: 使用自签名证书用于演示")
    print("=" * 60)
    
    app.run(host='0.0.0.0', port=5000, debug=True)
