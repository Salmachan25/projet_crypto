#!/bin/bash

set -e

PKI_DIR="$HOME/pki_project"
ROOT_CA_DIR="$PKI_DIR/root_ca"
INT_CA_DIR="$PKI_DIR/intermediate_ca"

echo "=== Création de l'Intermediate CA ==="

# Vérification que Root CA existe
if [ ! -f "$ROOT_CA_DIR/certs/root_ca.cert.pem" ]; then
    echo "Erreur: Root CA n'existe pas. Créez d'abord le Root CA."
    exit 1
fi

# Initialisation des fichiers de base
cd "$INT_CA_DIR"
touch index.txt
echo 1000 > serial
echo 1000 > crlnumber

# Génération de la clé privée Intermediate CA
echo "Génération de la clé privée Intermediate CA..."
openssl genrsa -aes256 -out private/intermediate_ca.key.pem 4096
chmod 400 private/intermediate_ca.key.pem

# Génération du CSR pour l'Intermediate CA
echo "Génération du CSR Intermediate CA..."
openssl req -config openssl_intermediate.cnf \
    -new -sha256 \
    -key private/intermediate_ca.key.pem \
    -out csr/intermediate_ca.csr.pem

# Signature du certificat par le Root CA
echo "Signature du certificat Intermediate CA par Root CA..."
cd "$ROOT_CA_DIR"
openssl ca -config openssl_root.cnf \
    -extensions v3_intermediate_ca \
    -days 3650 -notext -md sha256 \
    -in "$INT_CA_DIR/csr/intermediate_ca.csr.pem" \
    -out "$INT_CA_DIR/certs/intermediate_ca.cert.pem"

chmod 444 "$INT_CA_DIR/certs/intermediate_ca.cert.pem"

# Création de la chaîne de certificats
echo "Création de la chaîne de certificats..."
cat "$INT_CA_DIR/certs/intermediate_ca.cert.pem" \
    "$ROOT_CA_DIR/certs/root_ca.cert.pem" > \
    "$INT_CA_DIR/certs/ca-chain.cert.pem"

chmod 444 "$INT_CA_DIR/certs/ca-chain.cert.pem"

# Génération de la première CRL
echo "Génération de la CRL initiale..."
cd "$INT_CA_DIR"
openssl ca -config openssl_intermediate.cnf \
    -gencrl -out crl/intermediate_ca.crl.pem

# Vérification du certificat
echo "=== Vérification du certificat Intermediate CA ==="
openssl x509 -noout -text -in "$INT_CA_DIR/certs/intermediate_ca.cert.pem"

# Vérification de la chaîne de confiance
echo "=== Vérification de la chaîne de confiance ==="
openssl verify -CAfile "$ROOT_CA_DIR/certs/root_ca.cert.pem" \
    "$INT_CA_DIR/certs/intermediate_ca.cert.pem"

echo "Intermediate CA créé avec succès!"
echo "Certificat Intermediate CA: $INT_CA_DIR/certs/intermediate_ca.cert.pem"
echo "Chaîne complète: $INT_CA_DIR/certs/ca-chain.cert.pem"
