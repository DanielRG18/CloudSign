"""
app.py — Servidor Flask mínimo para el sistema de Cartas Notariales Digitales.

Rutas:
  GET  /            -> interfaz web (emitir / verificar)
  POST /emitir       -> firma un documento y devuelve la "constancia" (JSON)
  POST /verificar     -> verifica un documento contra una constancia

Ejecutar:
  pip install -r requirements.txt
  python app.py
  abrir http://127.0.0.1:5000
"""
import json
import os

from flask import Flask, render_template, request, jsonify, send_file
import io

import crypto_core as cc

app = Flask(__name__)
STORAGE_DIR = os.path.join(os.path.dirname(__file__), "storage")
os.makedirs(STORAGE_DIR, exist_ok=True)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/emitir", methods=["POST"])
def emitir():
    """
    Recibe el contenido de la carta (texto pegado o archivo subido) y
    devuelve la constancia firmada (JSON) + reporte de evidencia.
    """
    document_bytes = None
    filename = "carta.txt"

    if "archivo" in request.files and request.files["archivo"].filename:
        f = request.files["archivo"]
        filename = f.filename
        document_bytes = f.read()
    else:
        texto = request.form.get("texto", "")
        if not texto.strip():
            return jsonify({"error": "Debes escribir texto o subir un archivo."}), 400
        document_bytes = texto.encode("utf-8")

    signer_name = request.form.get("firmante", cc.ISSUER_CN) or cc.ISSUER_CN

    constancia = cc.emitir_carta_notarial(document_bytes, signer_name=signer_name)

    reporte = {
        "emisor_firmante": signer_name,
        "algoritmo": constancia["documento"]["algoritmo_firma"],
        "hash_documento_sha256": constancia["documento"]["hash_sha256_hex"],
        "timestamp_fecha_cierta_utc": constancia["sello_tiempo"]["timestamp_utc"],
        "estado_certificado_emisor": constancia["emisor"]["certificado_estado"],
        "estado_certificado_tsa": constancia["sello_tiempo"]["tsa_certificado_estado"],
        "resultado": "EMITIDA",
    }

    return jsonify({
        "reporte": reporte,
        "constancia": constancia,
        "documento_base64": __import__("base64").b64encode(document_bytes).decode(),
        "nombre_archivo_original": filename,
    })


@app.route("/verificar", methods=["POST"])
def verificar():
    """
    Recibe: archivo del documento a verificar + archivo/JSON de la constancia.
    Devuelve el reporte binario de verificación (APROBADA / RECHAZADA).
    """
    if "documento" not in request.files or not request.files["documento"].filename:
        return jsonify({"error": "Debes subir el documento a verificar."}), 400

    document_bytes = request.files["documento"].read()

    constancia_raw = None
    if "constancia" in request.files and request.files["constancia"].filename:
        constancia_raw = request.files["constancia"].read()
    else:
        constancia_raw = request.form.get("constancia_json", "").encode("utf-8")

    if not constancia_raw or not constancia_raw.strip():
        return jsonify({"error": "Debes subir/pegar la constancia (JSON) emitida."}), 400

    try:
        constancia = json.loads(constancia_raw)
    except json.JSONDecodeError:
        return jsonify({"error": "La constancia no es un JSON válido."}), 400

    try:
        resultado = cc.verificar_carta_notarial(document_bytes, constancia)
    except Exception as e:
        return jsonify({"error": f"Error al verificar: {e}"}), 400

    reporte = {
        "emisor_firmante": constancia.get("emisor", {}).get("common_name", "desconocido"),
        "algoritmo": constancia.get("documento", {}).get("algoritmo_firma", "desconocido"),
        "hash_documento_original_h2": resultado["hash_declarado_h2"],
        "hash_recomputado_h1": resultado["hash_recomputado_h1"],
        "hashes_coinciden": resultado["hash_coincide"],
        "firma_emisor_valida": resultado["firma_emisor_valida"],
        "sello_tiempo_valido": resultado["sello_tiempo_firma_valida"],
        "sello_tiempo_vinculado": resultado["sello_tiempo_vinculado_al_documento"],
        "timestamp_fecha_cierta_utc": resultado["timestamp_utc"],
        "estado_certificado_emisor": resultado["emisor_certificado_estado"],
        "estado_certificado_tsa": resultado["tsa_certificado_estado"],
        "resultado": resultado["resultado"],
        "mensaje": resultado["mensaje"],
    }

    return jsonify({"reporte": reporte})


if __name__ == "__main__":
    cc.ensure_default_identities()
    print("Identidades (Emisor / TSA) listas en ./keys")
    print("Servidor disponible en http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=True)
