"""
crypto_core.py

- RSA 2048 bits
- SHA-256
- Firma PKCS#1 v1.5 (RSA-SHA256), el esquema clásico usado en firma de
    documentos / PDF / código.
- Certificados X.509 autofirmados (PKI básica) para representar la
    identidad del Emisor y de la Autoridad de Sellado de Tiempo (TSA).

"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import os
import uuid
from dataclasses import dataclass, asdict
from typing import Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.x509.oid import NameOID
from cryptography.exceptions import InvalidSignature

KEYS_DIR = os.path.join(os.path.dirname(__file__), "keys")
os.makedirs(KEYS_DIR, exist_ok=True)

RSA_KEY_SIZE = 2048
RSA_PUBLIC_EXPONENT = 65537


# --------------------------------------------------------------------------
# 1. Generación y gestión de identidad digital (PKI básica)
# --------------------------------------------------------------------------

def generate_identity(common_name: str, org: str = "PoC Notaria Digital",
                       valid_days: int = 365) -> Tuple[str, str]:
    """
    Genera un par de llaves RSA-2048 y un certificado X.509 autofirmado
    para `common_name` (p.ej. "Emisor" o "TSA-Notaria-Digital").

    Devuelve las rutas (private_key_path, cert_path). Si la identidad ya
    existe en disco, la reutiliza (no la regenera), tal como haría una PKI
    real que preserva la clave privada del sujeto.
    """
    priv_path = os.path.join(KEYS_DIR, f"{common_name}_private.pem")
    cert_path = os.path.join(KEYS_DIR, f"{common_name}_cert.pem")

    if os.path.exists(priv_path) and os.path.exists(cert_path):
        return priv_path, cert_path

    private_key = rsa.generate_private_key(
        public_exponent=RSA_PUBLIC_EXPONENT,
        key_size=RSA_KEY_SIZE,
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "MX"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)  # autofirmado: issuer == subject
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=valid_days))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,  # "non-repudiation"
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )

    with open(priv_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    return priv_path, cert_path


def load_private_key(path: str) -> RSAPrivateKey:
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_certificate(path_or_pem) -> x509.Certificate:
    """Acepta una ruta a archivo .pem o bytes/str con el PEM directamente."""
    if isinstance(path_or_pem, (bytes, str)) and (
        b"BEGIN CERTIFICATE" in (path_or_pem.encode() if isinstance(path_or_pem, str) else path_or_pem)
    ):
        data = path_or_pem.encode() if isinstance(path_or_pem, str) else path_or_pem
        return x509.load_pem_x509_certificate(data)
    with open(path_or_pem, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def cert_to_pem_str(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def check_certificate_status(cert: x509.Certificate) -> str:
    """
    Simulación de verificación tipo OCSP: no hay una CA/OCSP
    real (el certificado es autofirmado), así que el "estado" se calcula
    de forma real y verificable a partir de los campos del propio
    certificado X.509 (vigencia temporal), que sí son criptográficamente
    reales (firmados por el emisor del certificado).
    """
    now = dt.datetime.now(dt.timezone.utc)
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    if now < not_before:
        return "NO_VIGENTE_AUN"
    if now > not_after:
        return "EXPIRADO"
    return "GOOD / VIGENTE"


# --------------------------------------------------------------------------
# 2. Hash + Firma del documento
# --------------------------------------------------------------------------

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sign_document(document_bytes: bytes, private_key: RSAPrivateKey) -> Tuple[str, str]:
    """
    H(M) = SHA-256(M)
    S    = Firmar(H(M), K_priv)   usando RSASSA-PKCS1-v1_5 con SHA-256
           (estándar "RSA-SHA256" usado en firma de documentos/PDF/JAR).

    Nota: la librería recibe el mensaje completo y aplica SHA-256
    internamente antes de firmar (comportamiento estándar de PKCS#1v1.5);
    calculamos también el hash por separado para exhibirlo en el reporte
    y para el flujo de verificación H1 == H2.
    """
    doc_hash_hex = sha256_hex(document_bytes)
    signature = private_key.sign(
        document_bytes,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    return doc_hash_hex, base64.b64encode(signature).decode()


def verify_document_signature(
    document_bytes: bytes, signature_b64: str, public_key: RSAPublicKey
) -> Tuple[bool, str]:
    """
    H1 = SHA-256(M) recomputado sobre el documento recibido.
    Verifica matemáticamente S contra H(M) usando K_pub.

    Devuelve (es_valida: bool, h1_hex: str).
    Si se altera un solo carácter del documento, H1 cambia y/o la
    verificación criptográfica de la firma falla -> es_valida = False.
    """
    h1_hex = sha256_hex(document_bytes)
    try:
        public_key.verify(
            base64.b64decode(signature_b64),
            document_bytes,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return True, h1_hex
    except InvalidSignature:
        return False, h1_hex


# --------------------------------------------------------------------------
# 3. Sello de tiempo / "Fecha Cierta" (emulación de TSP / RFC 3161)
# --------------------------------------------------------------------------
#
# RFC 3161 real requiere una Autoridad de Sellado de Tiempo (TSA) externa
# y acreditada. Aqui se modela el mismo principio criptográfico:
# una identidad INDEPENDIENTE (par de llaves + certificado propio) actúa
# como TSA local y firma digitalmente la tupla (hash_del_documento,
# timestamp_utc, nonce), vinculando de forma verificable el documento a
# un instante de tiempo. La firma de la TSA es tan real como la del
# emisor (misma primitiva RSA-SHA256); lo único "de PoC" es que la TSA
# vive en este mismo servidor en vez de ser un tercero acreditado.

def generate_timestamp_token(doc_hash_hex: str, tsa_private_key: RSAPrivateKey) -> dict:
    timestamp_utc = dt.datetime.now(dt.timezone.utc).isoformat()
    nonce = uuid.uuid4().hex
    tsp_payload = json.dumps(
        {"doc_hash": doc_hash_hex, "timestamp_utc": timestamp_utc, "nonce": nonce},
        sort_keys=True,
    ).encode()

    tsa_signature = tsa_private_key.sign(
        tsp_payload,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )

    return {
        "doc_hash": doc_hash_hex,
        "timestamp_utc": timestamp_utc,
        "nonce": nonce,
        "tsa_signature_b64": base64.b64encode(tsa_signature).decode(),
    }


def verify_timestamp_token(token: dict, tsa_public_key: RSAPublicKey) -> bool:
    tsp_payload = json.dumps(
        {
            "doc_hash": token["doc_hash"],
            "timestamp_utc": token["timestamp_utc"],
            "nonce": token["nonce"],
        },
        sort_keys=True,
    ).encode()
    try:
        tsa_public_key.verify(
            base64.b64decode(token["tsa_signature_b64"]),
            tsp_payload,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


# --------------------------------------------------------------------------
# Helpers de alto nivel usados por la app / CLI
# --------------------------------------------------------------------------

ISSUER_CN = "Emisor-Notaria-Digital"
TSA_CN = "TSA-Notaria-Digital"


def ensure_default_identities():
    """Crea (si no existen) la identidad del Emisor y la de la TSA."""
    issuer_priv, issuer_cert = generate_identity(ISSUER_CN)
    tsa_priv, tsa_cert = generate_identity(TSA_CN, org="PoC TSA Independiente")
    return {
        "issuer_priv": issuer_priv,
        "issuer_cert": issuer_cert,
        "tsa_priv": tsa_priv,
        "tsa_cert": tsa_cert,
    }


def emitir_carta_notarial(document_bytes: bytes, signer_name: str = ISSUER_CN) -> dict:
    """
    Flujo completo de emisión:
      1. Carga/crea identidad del emisor y de la TSA.
      2. Calcula H(M) y firma S = Firmar(H(M), K_priv).
      3. Genera sello de tiempo firmado por la TSA, vinculado a H(M).
      4. Empaqueta todo en una "constancia" (evidencia) verificable.
    """
    ids = ensure_default_identities()

    issuer_key = load_private_key(ids["issuer_priv"])
    issuer_cert = load_certificate(ids["issuer_cert"])

    tsa_key = load_private_key(ids["tsa_priv"])
    tsa_cert = load_certificate(ids["tsa_cert"])

    doc_hash_hex, signature_b64 = sign_document(document_bytes, issuer_key)
    tsp_token = generate_timestamp_token(doc_hash_hex, tsa_key)

    constancia = {
        "version": "1.0",
        "tipo": "Carta Notarial Digital - Constancia de Emision",
        "emisor": {
            "common_name": signer_name,
            "certificado_pem": cert_to_pem_str(issuer_cert),
            "certificado_estado": check_certificate_status(issuer_cert),
        },
        "documento": {
            "hash_sha256_hex": doc_hash_hex,
            "algoritmo_firma": "RSA-SHA256 (PKCS#1 v1.5, RSA-2048)",
            "firma_b64": signature_b64,
        },
        "sello_tiempo": {
            **tsp_token,
            "tsa_common_name": TSA_CN,
            "tsa_certificado_pem": cert_to_pem_str(tsa_cert),
            "tsa_certificado_estado": check_certificate_status(tsa_cert),
        },
        "emitido_en_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
    }
    return constancia


def verificar_carta_notarial(document_bytes: bytes, constancia: dict) -> dict:
    """
    Flujo completo de verificación / auditoría:
      H1 = SHA-256(M) recomputado sobre el documento recibido.
      H2 = hash declarado en la constancia (el que se firmó).
      - Verifica la firma del emisor sobre el documento (criptográficamente).
      - Verifica la firma de la TSA sobre el sello de tiempo.
      - Verifica que el hash sellado por la TSA == hash del documento.
      Retorna un reporte estructurado con estado APROBADA / RECHAZADA.
    """
    issuer_cert = load_certificate(constancia["emisor"]["certificado_pem"])
    issuer_pub = issuer_cert.public_key()

    tsa_cert = load_certificate(constancia["sello_tiempo"]["tsa_certificado_pem"])
    tsa_pub = tsa_cert.public_key()

    h2_declared = constancia["documento"]["hash_sha256_hex"]
    signature_b64 = constancia["documento"]["firma_b64"]

    firma_valida, h1 = verify_document_signature(document_bytes, signature_b64, issuer_pub)
    hash_coincide = (h1 == h2_declared)

    tsp_token = {
        "doc_hash": constancia["sello_tiempo"]["doc_hash"],
        "timestamp_utc": constancia["sello_tiempo"]["timestamp_utc"],
        "nonce": constancia["sello_tiempo"]["nonce"],
        "tsa_signature_b64": constancia["sello_tiempo"]["tsa_signature_b64"],
    }
    sello_valido = verify_timestamp_token(tsp_token, tsa_pub)
    sello_vinculado = (tsp_token["doc_hash"] == h1)

    integridad_ok = firma_valida and hash_coincide
    sello_ok = sello_valido and sello_vinculado
    resultado_final = integridad_ok and sello_ok

    return {
        "hash_recomputado_h1": h1,
        "hash_declarado_h2": h2_declared,
        "hash_coincide": hash_coincide,
        "firma_emisor_valida": firma_valida,
        "emisor_certificado_estado": check_certificate_status(issuer_cert),
        "sello_tiempo_firma_valida": sello_valido,
        "sello_tiempo_vinculado_al_documento": sello_vinculado,
        "tsa_certificado_estado": check_certificate_status(tsa_cert),
        "timestamp_utc": constancia["sello_tiempo"]["timestamp_utc"],
        "integridad_autenticidad_ok": integridad_ok,
        "sello_tiempo_ok": sello_ok,
        "resultado": "APROBADA" if resultado_final else "RECHAZADA",
        "mensaje": (
            "Firma Válida e Íntegra: el documento no ha sido alterado y "
            "la identidad del firmante es matemáticamente verificable."
            if resultado_final
            else "Firma Inválida o Documento Alterado: la verificación "
            "criptográfica no coincide con la constancia presentada."
        ),
    }
