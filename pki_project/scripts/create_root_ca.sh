#!/bin/bash

set -e

PKI_DIR="$HOME/pki_project"
ROOT_CA_DIR="$PKI_DIR/root_ca"

echo "=== Création du Root CA ==="

# Initialisation des fichiers de base
cd "$ROOT_CA_DIR"
touch index.txt
echo 1000 > serial
echo 1000 > crlnumber

# Génération de la clé privée Root CA (4096 bits RSA)
echo "Génération de la clé privée Root CA..."
openssl genrsa -aes256 -out private/root_ca.key.pem 4096
chmod 400 private/root_ca.key.pem

# Génération du certificat auto-signé Root CA
echo "Génération du certificat Root CA..."
openssl req -config openssl_root.cnf \
    -key private/root_ca.key.pem \
    -new -x509 -days 7300 -sha256 \
    -extensions v3_ca \
    -out certs/root_ca.cert.pem

chmod 444 certs/root_ca.cert.pem

# Génération de la première CRL
echo "Génération de la CRL initiale..."
openssl ca -config openssl_root.cnf \
    -gencrl -out crl/root_ca.crl.pem

# Vérification du certificat
echo "=== Vérification du certificat Root CA ==="
openssl x509 -noout -text -in certs/root_ca.cert.pem

echo "Root CA créé avec succès!"
echo "Certificat Root CA: $ROOT_CA_DIR/certs/root_ca.cert.pem"
