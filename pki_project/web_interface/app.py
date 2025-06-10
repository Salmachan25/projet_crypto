from flask import Flask, render_template, request, redirect, url_for, flash, send_file
import os
import subprocess
import tempfile
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from datetime import datetime
import json
import getpass

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'

PKI_DIR = os.path.expanduser('~/pki_project')
ROOT_CA_DIR = os.path.join(PKI_DIR, 'root_ca')
INT_CA_DIR = os.path.join(PKI_DIR, 'intermediate_ca')
CERT_DIR = os.path.join(PKI_DIR, 'certificates')

# Global variable to store passphrase (in memory only)
INTERMEDIATE_CA_PASSPHRASE = None

def load_certificate(cert_path):
    """Charge et parse un certificat X.509"""
    try:
        with open(cert_path, 'rb') as f:
            cert = x509.load_pem_x509_certificate(f.read())
        return cert
    except Exception as e:
        return None

def get_certificate_info(cert_path):
    """Extrait les informations d'un certificat"""
    cert = load_certificate(cert_path)
    if not cert:
        return None
    
    return {
        'subject': cert.subject.rfc4514_string(),
        'issuer': cert.issuer.rfc4514_string(),
        'serial_number': str(cert.serial_number),
        'not_valid_before': cert.not_valid_before,
        'not_valid_after': cert.not_valid_after,
        'is_expired': cert.not_valid_after < datetime.now()
    }

def ensure_directories():
    """Ensure all required directories exist with proper permissions"""
    directories = [
        os.path.join(CERT_DIR, 'servers'),
        os.path.join(CERT_DIR, 'clients')
    ]
    
    for directory in directories:
        try:
            os.makedirs(directory, mode=0o775, exist_ok=True)
        except PermissionError as e:
            print(f"Permission error creating directory {directory}: {e}")
        except Exception as e:
            print(f"Error creating directory {directory}: {e}")

def create_certificate_with_passphrase(cert_type, common_name, passphrase):
    """Create certificate using OpenSSL commands with passphrase"""
    try:
        # Determine the output directory and file paths
        output_dir = os.path.join(CERT_DIR, f"{cert_type}s")
        key_file = os.path.join(output_dir, f"{common_name}.key.pem")
        csr_file = os.path.join(output_dir, f"{common_name}.csr.pem")
        cert_file = os.path.join(output_dir, f"{common_name}.cert.pem")
        
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
        
        # Step 1: Generate private key
        subprocess.run([
            'openssl', 'genrsa', '-out', key_file, '2048'
        ], check=True, capture_output=True, text=True)
        
        # Step 2: Create certificate signing request (CSR)
        subprocess.run([
            'openssl', 'req', '-new', '-key', key_file, '-out', csr_file,
            '-subj', f'/CN={common_name}'
        ], check=True, capture_output=True, text=True)
        
        # Step 3: Sign the certificate with intermediate CA
        os.chdir(INT_CA_DIR)
        
        # Prepare the signing command
        sign_cmd = [
            'openssl', 'ca', '-config', 'openssl_intermediate.cnf',
            '-extensions', f'{cert_type}_cert',
            '-days', '365', '-notext', '-md', 'sha256',
            '-in', csr_file, '-out', cert_file,
            '-batch', '-passin', f'pass:{passphrase}'
        ]
        
        subprocess.run(sign_cmd, check=True, capture_output=True, text=True)
        
        # Clean up CSR file
        os.remove(csr_file)
        
        return True, "Certificate created successfully"
        
    except subprocess.CalledProcessError as e:
        return False, f"OpenSSL error: {e.stderr}"
    except Exception as e:
        return False, f"Unexpected error: {str(e)}"

@app.route('/')
def index():
    """Page d'accueil de la PKI"""
    # Statistiques de la PKI
    stats = {
        'root_ca_exists': os.path.exists(os.path.join(ROOT_CA_DIR, 'certs/root_ca.cert.pem')),
        'intermediate_ca_exists': os.path.exists(os.path.join(INT_CA_DIR, 'certs/intermediate_ca.cert.pem')),
        'total_certificates': 0,
        'server_certificates': 0,
        'client_certificates': 0,
        'passphrase_set': INTERMEDIATE_CA_PASSPHRASE is not None
    }
    
    # Compter les certificats
    server_dir = os.path.join(CERT_DIR, 'servers')
    client_dir = os.path.join(CERT_DIR, 'clients')
    
    if os.path.exists(server_dir):
        stats['server_certificates'] = len([f for f in os.listdir(server_dir) if f.endswith('.cert.pem')])
    
    if os.path.exists(client_dir):
        stats['client_certificates'] = len([f for f in os.listdir(client_dir) if f.endswith('.cert.pem')])
    
    stats['total_certificates'] = stats['server_certificates'] + stats['client_certificates']
    
    return render_template('index.html', stats=stats)

@app.route('/set_passphrase', methods=['GET', 'POST'])
def set_passphrase():
    """Set the intermediate CA passphrase"""
    global INTERMEDIATE_CA_PASSPHRASE
    
    if request.method == 'POST':
        passphrase = request.form['passphrase']
        
        # Test the passphrase by trying to read the intermediate CA private key
        try:
            int_ca_key_path = os.path.join(INT_CA_DIR, 'private/intermediate_ca.key.pem')
            test_cmd = [
                'openssl', 'rsa', '-in', int_ca_key_path,
                '-passin', f'pass:{passphrase}', '-noout'
            ]
            subprocess.run(test_cmd, check=True, capture_output=True, text=True)
            
            # If successful, store the passphrase
            INTERMEDIATE_CA_PASSPHRASE = passphrase
            flash('Passphrase set successfully!', 'success')
            return redirect(url_for('index'))
            
        except subprocess.CalledProcessError:
            flash('Invalid passphrase. Please try again.', 'error')
    
    return render_template('set_passphrase.html')

@app.route('/certificates')
def list_certificates():
    """Liste tous les certificats"""
    certificates = []
    
    # Certificats serveurs
    server_dir = os.path.join(CERT_DIR, 'servers')
    if os.path.exists(server_dir):
        for cert_file in os.listdir(server_dir):
            if cert_file.endswith('.cert.pem'):
                cert_path = os.path.join(server_dir, cert_file)
                cert_info = get_certificate_info(cert_path)
                if cert_info:
                    cert_info['type'] = 'Server'
                    cert_info['filename'] = cert_file
                    certificates.append(cert_info)
    
    # Certificats clients
    client_dir = os.path.join(CERT_DIR, 'clients')
    if os.path.exists(client_dir):
        for cert_file in os.listdir(client_dir):
            if cert_file.endswith('.cert.pem'):
                cert_path = os.path.join(client_dir, cert_file)
                cert_info = get_certificate_info(cert_path)
                if cert_info:
                    cert_info['type'] = 'Client'
                    cert_info['filename'] = cert_file
                    certificates.append(cert_info)
    
    return render_template('certificates.html', certificates=certificates)

@app.route('/create_certificate', methods=['GET', 'POST'])
def create_certificate():
    """Formulaire de création de certificat"""
    global INTERMEDIATE_CA_PASSPHRASE
    
    if request.method == 'POST':
        # Check if passphrase is set
        if not INTERMEDIATE_CA_PASSPHRASE:
            flash('Please set the intermediate CA passphrase first.', 'error')
            return redirect(url_for('set_passphrase'))
        
        cert_type = request.form['type']
        common_name = request.form['common_name']
        
        # Ensure directories exist
        ensure_directories()
        
        success, message = create_certificate_with_passphrase(cert_type, common_name, INTERMEDIATE_CA_PASSPHRASE)
        
        if success:
            flash(f'Certificate {cert_type} for {common_name} created successfully!', 'success')
        else:
            flash(f'Error creating certificate: {message}', 'error')
        
        return redirect(url_for('list_certificates'))
    
    return render_template('create_certificate.html')

@app.route('/ca_info')
def ca_info():
    """Informations sur les autorités de certification"""
    root_ca_info = None
    int_ca_info = None
    
    root_ca_path = os.path.join(ROOT_CA_DIR, 'certs/root_ca.cert.pem')
    if os.path.exists(root_ca_path):
        root_ca_info = get_certificate_info(root_ca_path)
    
    int_ca_path = os.path.join(INT_CA_DIR, 'certs/intermediate_ca.cert.pem')
    if os.path.exists(int_ca_path):
        int_ca_info = get_certificate_info(int_ca_path)
    
    return render_template('ca_info.html', root_ca=root_ca_info, intermediate_ca=int_ca_info)

@app.route('/crl/<ca_type>')
def download_crl(ca_type):
    """Téléchargement des listes de révocation"""
    if ca_type == 'root':
        crl_path = os.path.join(ROOT_CA_DIR, 'crl/root_ca.crl.pem')
    elif ca_type == 'intermediate':
        crl_path = os.path.join(INT_CA_DIR, 'crl/intermediate_ca.crl.pem')
    else:
        return "CRL non trouvée", 404
    
    if os.path.exists(crl_path):
        return send_file(crl_path, as_attachment=True)
    else:
        return "CRL non trouvée", 404

@app.route('/revoke_certificate', methods=['POST'])
def revoke_certificate():
    """Révocation d'un certificat"""
    global INTERMEDIATE_CA_PASSPHRASE
    
    if not INTERMEDIATE_CA_PASSPHRASE:
        flash('Please set the intermediate CA passphrase first.', 'error')
        return redirect(url_for('set_passphrase'))
    
    cert_type = request.form['type']
    filename = request.form['filename']
    
    cert_path = os.path.join(CERT_DIR, f'{cert_type}s', filename)
    
    try:
        # Révoquer le certificat
        os.chdir(INT_CA_DIR)
        subprocess.run([
            'openssl', 'ca', '-config', 'openssl_intermediate.cnf',
            '-revoke', cert_path, '-passin', f'pass:{INTERMEDIATE_CA_PASSPHRASE}'
        ], check=True, capture_output=True, text=True)
        
        # Générer une nouvelle CRL
        subprocess.run([
            'openssl', 'ca', '-config', 'openssl_intermediate.cnf',
            '-gencrl', '-out', 'crl/intermediate_ca.crl.pem',
            '-passin', f'pass:{INTERMEDIATE_CA_PASSPHRASE}'
        ], check=True, capture_output=True, text=True)
        
        flash(f'Certificate {filename} revoked successfully!', 'success')
    except subprocess.CalledProcessError as e:
        flash(f'Error during revocation: {e.stderr}', 'error')
    
    return redirect(url_for('list_certificates'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
