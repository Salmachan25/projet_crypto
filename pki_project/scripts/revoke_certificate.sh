#!/bin/bash

set -e

if [ $# -ne 2 ]; then
    echo "Usage: $0 <type> <common_name>"
    echo "Types: server, client"
    echo "Exemple: $0 server www.example.com"
    exit 1
fi

TYPE=$1
COMMON_NAME=$2

PKI_DIR="$HOME/pki_project"
INT_CA_DIR="$PKI_DIR/intermediate_ca"
CERT_DIR="$PKI_DIR/certificates"

CERT_PATH="$CERT_DIR/${TYPE}s/${COMMON_NAME}.cert.pem"

echo "=== Révocation du certificat $TYPE pour $COMMON_NAME ==="

# Vérification que le certificat existe
if [ ! -f "$CERT_PATH" ]; then
    echo "Erreur: Certificat non trouvé: $CERT_PATH"
    exit 1
fi

# Révocation du certificat
echo "Révocation du certificat..."
cd "$INT_CA_DIR"
openssl ca -config openssl_intermediate.cnf \
    -revoke "$CERT_PATH"

# Génération d'une nouvelle CRL
echo "Génération de la nouvelle CRL..."
openssl ca -config openssl_intermediate.cnf \
    -gencrl -out crl/intermediate_ca.crl.pem

echo "Certificat révoqué avec succès!"
echo "Nouvelle CRL générée: $INT_CA_DIR/crl/intermediate_ca.crl.pem"
