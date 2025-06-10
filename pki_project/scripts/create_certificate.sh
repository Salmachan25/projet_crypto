#!/bin/bash

set -e

if [ $# -ne 2 ]; then
    echo "Usage: $0 <type> <common_name>"
    echo "Types: server, client"
    echo "Exemple: $0 server www.example.com"
    echo "Exemple: $0 client john.doe"
    exit 1
fi

TYPE=$1
COMMON_NAME=$2

PKI_DIR="$HOME/pki_project"
INT_CA_DIR="$PKI_DIR/intermediate_ca"
CERT_DIR="$PKI_DIR/certificates"

echo "=== Génération d'un certificat $TYPE pour $COMMON_NAME ==="

# Vérification que l'Intermediate CA existe
if [ ! -f "$INT_CA_DIR/certs/intermediate_ca.cert.pem" ]; then
    echo "Erreur: Intermediate CA n'existe pas. Créez d'abord l'Intermediate CA."
    exit 1
fi

# Vérification du type
if [ "$TYPE" != "server" ] && [ "$TYPE" != "client" ]; then
    echo "Erreur: Type doit être 'server' ou 'client'"
    exit 1
fi

# Génération de la clé privée
echo "Génération de la clé privée..."
openssl genrsa -out "$CERT_DIR/${TYPE}s/${COMMON_NAME}.key.pem" 2048
chmod 400 "$CERT_DIR/${TYPE}s/${COMMON_NAME}.key.pem"

# Génération du CSR
echo "Génération du CSR..."
openssl req -config "$INT_CA_DIR/openssl_intermediate.cnf" \
    -key "$CERT_DIR/${TYPE}s/${COMMON_NAME}.key.pem" \
    -new -sha256 \
    -out "$CERT_DIR/${TYPE}s/${COMMON_NAME}.csr.pem" \
    -subj "/C=MA/ST=Tanger-Tetouan-Al Hoceima/L=Tangier/O=MMSD University/OU=IT Department/CN=${COMMON_NAME}"

# Signature du certificat
echo "Signature du certificat..."
cd "$INT_CA_DIR"
openssl ca -config openssl_intermediate.cnf \
    -extensions "${TYPE}_cert" \
    -days 365 -notext -md sha256 \
    -in "$CERT_DIR/${TYPE}s/${COMMON_NAME}.csr.pem" \
    -out "$CERT_DIR/${TYPE}s/${COMMON_NAME}.cert.pem" \
    -batch

chmod 444 "$CERT_DIR/${TYPE}s/${COMMON_NAME}.cert.pem"

# Création du bundle (certificat + chaîne)
echo "Création du bundle certificat..."
cat "$CERT_DIR/${TYPE}s/${COMMON_NAME}.cert.pem" \
    "$INT_CA_DIR/certs/ca-chain.cert.pem" > \
    "$CERT_DIR/${TYPE}s/${COMMON_NAME}-bundle.cert.pem"

# Vérification du certificat
echo "=== Vérification du certificat ==="
openssl x509 -noout -text -in "$CERT_DIR/${TYPE}s/${COMMON_NAME}.cert.pem"

# Vérification de la chaîne de confiance
echo "=== Vérification de la chaîne de confiance ==="
openssl verify -CAfile "$INT_CA_DIR/certs/ca-chain.cert.pem" \
    "$CERT_DIR/${TYPE}s/${COMMON_NAME}.cert.pem"

echo "Certificat $TYPE pour $COMMON_NAME créé avec succès!"
echo "Clé privée: $CERT_DIR/${TYPE}s/${COMMON_NAME}.key.pem"
echo "Certificat: $CERT_DIR/${TYPE}s/${COMMON_NAME}.cert.pem"
echo "Bundle: $CERT_DIR/${TYPE}s/${COMMON_NAME}-bundle.cert.pem"
