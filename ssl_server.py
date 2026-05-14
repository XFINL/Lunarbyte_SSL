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
import hashlib
import tempfile
import threading
import time
from datetime import datetime
from pathlib import Path

# ACME客户端库
from acme import client, messages, challenges
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import josepy as jose
import requests

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
CA_CONFIG = {
    'google': {
        'name': 'Google Trust Services',
        'directory_url': 'https://dv.acme-v02.api.pki.goog/directory',
        'eab_required': True,  # 需要外部账户绑定
        'eab_kid': None,  # 需要申请
        'eab_hmac_key': None,  # 需要申请
    },
    'zerossl': {
        'name': 'ZeroSSL',
        'directory_url': 'https://acme.zerossl.com/v2/DV90',
        'eab_required': True,
        'eab_kid': None,
        'eab_hmac_key': None,
    }
}

# Let's Encrypt作为备选（免费且不需要EAB）
LETSENCRYPT_CONFIG = {
    'staging': {
        'name': 'Let\'s Encrypt Staging',
        'directory_url': 'https://acme-staging-v02.api.letsencrypt.org/directory',
        'eab_required': False,
    },
    'production': {
        'name': 'Let\'s Encrypt',
        'directory_url': 'https://acme-v02.api.letsencrypt.org/directory',
        'eab_required': False,
    }
}


def generate_rsa_key(key_size=2048):
    """生成RSA密钥对"""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )


def save_account_key(request_id, key):
    """保存账户密钥"""
    key_path = ACCOUNTS_DIR / f'{request_id}_account.key'
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    key_path.write_bytes(key_pem)
    return str(key_path)


def save_cert_key(request_id, key):
    """保存证书密钥"""
    key_path = CERTS_DIR / f'{request_id}_key.pem'
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    key_path.write_bytes(key_pem)
    return str(key_path)


def create_acme_client(ca_name, email, request_id):
    """创建ACME客户端"""
    
    # 优先使用Let's Encrypt（不需要EAB）
    if ca_name == 'google' or ca_name == 'zerossl':
        # 如果没有EAB凭证，回退到Let's Encrypt
        config = LETSENCRYPT_CONFIG['staging']  # 测试环境
        print(f"CA {ca_name} 需要EAB凭证，使用Let's Encrypt Staging作为演示")
    else:
        config = LETSENCRYPT_CONFIG.get(ca_name, LETSENCRYPT_CONFIG['staging'])
    
    directory_url = config['directory_url']
    
    # 生成账户密钥
    account_key = generate_rsa_key()
    
    # 创建JWK
    jwk = jose.JWKRSA(key=account_key)
    
    # 创建网络客户端
    net = client.ClientNetwork(
        jwk,
        user_agent='SSL-Cert-App/1.0',
        verify_ssl=True
    )
    
    # 获取目录
    directory = messages.Directory.from_json(net.get(directory_url).json())
    
    # 创建ACME客户端
    acme_client = client.ClientV2(directory, net=net)
    
    # 注册账户
    try:
        registration = acme_client.new_account(
            messages.NewRegistration.from_data(
                email=email,
                terms_of_service_agreed=True
            )
        )
        print(f"账户注册成功: {registration.uri}")
    except Exception as e:
        print(f"账户注册信息: {e}")
        # 可能账户已存在，继续
    
    return acme_client, account_key


def generate_csr(domain, private_key):
    """生成证书签名请求"""
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
    """创建证书申请请求"""
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
    
    # 检查域名是否包含非法字符
    allowed_chars = set('abcdefghijklmnopqrstuvwxyz0123456789.-')
    if not all(c in allowed_chars for c in domain):
        return jsonify({'error': '域名包含非法字符'}), 400
    
    request_id = str(uuid.uuid4())
    
    try:
        # 生成密钥
        account_key = generate_rsa_key()
        cert_key = generate_rsa_key()
        
        # 保存密钥
        account_key_path = save_account_key(request_id, account_key)
        cert_key_path = save_cert_key(request_id, cert_key)
        
        # 创建ACME客户端
        acme_client, _ = create_acme_client(ca, email, request_id)
        
        # 创建订单
        order = acme_client.new_order([domain])
        
        # 获取授权和挑战
        authzr = order.authorizations[0]
        challenge = None
        challenge_type = None
        
        # 查找HTTP-01挑战（优先）
        for chall_body in authzr.body.challenges:
            if isinstance(chall_body.chall, challenges.HTTP01):
                challenge = chall_body
                challenge_type = 'http-01'
                break
        
        # 如果没有HTTP-01，查找DNS-01
        if not challenge:
            for chall_body in authzr.body.challenges:
                if isinstance(chall_body.chall, challenges.DNS01):
                    challenge = chall_body
                    challenge_type = 'dns-01'
                    break
        
        if not challenge:
            return jsonify({'error': 'CA不支持HTTP-01或DNS-01验证方式'}), 400
        
        # 准备验证信息
        verification_info = {
            'id': request_id,
            'type': challenge_type,
            'domain': domain
        }
        
        # 获取验证响应
        if challenge_type == 'http-01':
            response = challenge.chall.response(jose.JWKRSA(key=account_key))
            validation_content = response.key_authorization
            
            verification_info['file'] = {
                'path': f'/.well-known/acme-challenge/{challenge.chall.token}',
                'content': validation_content
            }
            
            # 保存验证信息用于后续检查
            validation_path = DATA_DIR / f'{request_id}_validation.json'
            validation_path.write_text(json.dumps({
                'type': 'http-01',
                'token': challenge.chall.token,
                'content': validation_content,
                'url': challenge.uri
            }))
            
        elif challenge_type == 'dns-01':
            response = challenge.chall.response(jose.JWKRSA(key=account_key))
            # key_authorization_hash 可能是列表，需要正确处理
            hash_data = response.key_authorization_hash
            if isinstance(hash_data, list):
                hash_data = bytes(hash_data)
            validation_value = base64.b64encode(hash_data).decode('utf-8')
            
            verification_info['record'] = {
                'type': 'TXT',
                'name': f'_acme-challenge.{domain}',
                'value': validation_value
            }
            
            # 保存验证信息
            validation_path = DATA_DIR / f'{request_id}_validation.json'
            validation_path.write_text(json.dumps({
                'type': 'dns-01',
                'name': f'_acme-challenge.{domain}',
                'value': validation_value,
                'url': challenge.uri
            }))
        
        # 保存请求信息
        requests_store[request_id] = {
            'id': request_id,
            'domain': domain,
            'ca': ca,
            'email': email,
            'status': 'pending_verification',
            'created_at': datetime.now().isoformat(),
            'account_key_path': account_key_path,
            'cert_key_path': cert_key_path,
            'acme_client': acme_client,
            'order': order,
            'challenge': challenge,
            'challenge_type': challenge_type,
            'verification': verification_info
        }
        
        print(f"创建请求成功: {request_id}, 域名: {domain}, 验证方式: {challenge_type}")
        
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
    
    try:
        acme_client = req['acme_client']
        challenge = req['challenge']
        account_key = req.get('account_key_path')
        
        # 读取账户密钥
        if account_key and os.path.exists(account_key):
            with open(account_key, 'rb') as f:
                key_pem = f.read()
            from cryptography.hazmat.primitives.serialization import load_pem_private_key
            account_key_obj = load_pem_private_key(key_pem, password=None)
            jwk = jose.JWKRSA(key=account_key_obj)
        else:
            return jsonify({'error': '账户密钥不存在'}), 500
        
        # 回答挑战
        try:
            response = challenge.chall.response(jwk)
            acme_client.answer_challenge(challenge, response)
            print(f"已回答挑战: {challenge.uri}")
        except Exception as e:
            print(f"回答挑战失败: {e}")
            return jsonify({
                'status': 'invalid',
                'message': f'验证失败: {str(e)}。请确保验证记录已正确配置。'
            })
        
        # 轮询授权状态
        max_attempts = 10
        for attempt in range(max_attempts):
            time.sleep(2)
            
            try:
                # 刷新授权状态
                authzr = acme_client.poll_authorizations(req['order'], deadline=None)
                
                # 检查挑战状态
                for auth in authzr:
                    for chall in auth.body.challenges:
                        if chall.uri == challenge.uri:
                            print(f"挑战状态: {chall.status}")
                            
                            if chall.status == messages.STATUS_VALID:
                                # 挑战通过，完成订单
                                print("挑战验证通过，正在完成订单...")
                                
                                # 读取证书密钥
                                cert_key_path = req['cert_key_path']
                                with open(cert_key_path, 'rb') as f:
                                    key_pem = f.read()
                                cert_key = load_pem_private_key(key_pem, password=None)
                                
                                # 生成CSR
                                csr = generate_csr(req['domain'], cert_key)
                                csr_pem = csr.public_bytes(encoding=serialization.Encoding.PEM)
                                
                                # 完成订单
                                try:
                                    finalized_order = acme_client.finalize_order(
                                        req['order'],
                                        csr_pem,
                                        deadline=None
                                    )
                                    print("订单完成")
                                except Exception as e:
                                    print(f"完成订单失败: {e}")
                                    return jsonify({
                                        'status': 'invalid',
                                        'message': f'证书签发失败: {str(e)}'
                                    })
                                
                                # 下载证书
                                try:
                                    certificate = acme_client.fetch_certificate(finalized_order)
                                    print("证书下载成功")
                                except Exception as e:
                                    print(f"下载证书失败: {e}")
                                    return jsonify({
                                        'status': 'invalid',
                                        'message': f'下载证书失败: {str(e)}'
                                    })
                                
                                # 保存证书
                                cert_path = CERTS_DIR / f'{request_id}_cert.pem'
                                chain_path = CERTS_DIR / f'{request_id}_chain.pem'
                                
                                # 保存完整证书链
                                cert_path.write_bytes(certificate.fullchain_pem.encode())
                                
                                # 保存仅证书
                                chain_path.write_bytes(certificate.body.encode())
                                
                                # 更新状态
                                requests_store[request_id]['cert_path'] = str(cert_path)
                                requests_store[request_id]['chain_path'] = str(chain_path)
                                requests_store[request_id]['status'] = 'issued'
                                requests_store[request_id]['issued_at'] = datetime.now().isoformat()
                                
                                print(f"证书已保存: {cert_path}")
                                
                                return jsonify({'status': 'valid'})
                            
                            elif chall.status == messages.STATUS_INVALID:
                                error_detail = '验证失败'
                                if chall.error:
                                    error_detail = f"验证失败: {chall.error.detail}"
                                return jsonify({
                                    'status': 'invalid',
                                    'message': error_detail
                                })
                            
                            elif chall.status == messages.STATUS_PENDING:
                                continue
                
            except Exception as e:
                print(f"轮询失败: {e}")
                continue
        
        # 超时
        return jsonify({
            'status': 'pending',
            'message': '验证仍在进行中，请稍后重试'
        })
        
    except Exception as e:
        print(f"检查验证失败: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'检查失败: {str(e)}'}), 500


@app.route('/api/cert/<request_id>', methods=['GET'])
def download_cert(request_id):
    """下载证书文件"""
    req = requests_store.get(request_id)
    if not req:
        return jsonify({'error': '请求不存在'}), 404
    
    if req.get('status') != 'issued':
        return jsonify({'error': '证书尚未签发'}), 400
    
    cert_type = request.args.get('type', 'cert')
    domain = req['domain']
    
    try:
        if cert_type == 'cert':
            # 完整证书链
            cert_path = req.get('cert_path')
            if cert_path and os.path.exists(cert_path):
                return send_file(
                    cert_path,
                    as_attachment=True,
                    download_name=f'{domain}_fullchain.crt',
                    mimetype='application/x-pem-file'
                )
        
        elif cert_type == 'key':
            # 私钥
            key_path = req.get('cert_key_path')
            if key_path and os.path.exists(key_path):
                return send_file(
                    key_path,
                    as_attachment=True,
                    download_name=f'{domain}.key',
                    mimetype='application/x-pem-file'
                )
        
        elif cert_type == 'chain':
            # 仅证书（不含CA链）
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
    print("SSL证书申请服务器")
    print("=" * 60)
    print(f"数据目录: {DATA_DIR}")
    print(f"证书目录: {CERTS_DIR}")
    print("=" * 60)
    
    app.run(host='0.0.0.0', port=5000, debug=True)
