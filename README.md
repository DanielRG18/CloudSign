# CloudSign: Cartas Notariales Digitales

Proyecto para la clase de Criptografía, que comprende un sistema de firma digitala de documentos. El proyecto busca garantizar que los documentos cumplan con:

- **Integridad**: cualquier cambio, incluso de un solo carácter, invalida la verificación.
- **Autenticidad**: la firma solo puede haberla generado quien posee la llave privada correspondiente a la llave pública / certificado presentado.
- **Fecha cierta**: un sello de tiempo firmado independientemente (emula TSP / RFC 3161) vincula el documento a un instante UTC.

Para la criptografía se utiliza: RSA-2048, SHA-256, firma PKCS#1 v1.5, certificados X.509 autofirmados, generados con la librería estándar `cryptography` (con OpenSSL por debajo).

---

## 1. Estructura del proyecto

```
carta-notarial/
├── crypto_core.py      # PKI, firma, hash, sellado de tiempo
├── app.py               # Flask
├── templates/index.html # Diseño de plataforma
├── requirements.txt
├── keys/                 # Se genera en tiempo de ejecución (llaves + certificados)
└── storage/              # Carpeta libre para guardar documentos/constancias
```

---

## 2. Instalación

Requiere Python 3.9+.

```bash
cd carta-notarial
python3 -m venv venv
source venv/bin/activate        # En Windows: venv\Scripts\activate

pip install -r requirements.txt
```

`requirements.txt` instala únicamente:
```
Flask>=3.0,<4.0
cryptography>=42.0
```

---

## 3. Ejecutar el servidor web (interfaz)

```bash
python app.py
```

Abre en el navegador: **http://127.0.0.1:5000**

Al arrancar, el servidor genera automáticamente (si no existen ya en `./keys`):
- La identidad del **Emisor** (llave privada RSA-2048 + certificado X.509 autofirmado).
- La identidad de la **TSA** (Autoridad de Sellado de Tiempo local, independiente del emisor).

### Flujo en la interfaz

**Pestaña "1. Emitir carta"**
1. Escribe el nombre del firmante.
2. Pega el texto de la carta o sube un archivo (PDF/TXT).
3. Clic en "Firmar".
4. El sistema muestra el reporte de evidencia y te permite descargar:
   - El **documento original**.
   - La **constancia** (`constancia.json`): contiene el hash, la firma RSA-SHA256, el certificado del emisor, el sello de tiempo firmado por la TSA y el certificado de la TSA. Este archivo es lo que se necesita, junto con el documento, para verificar la carta en el futuro.

**Pestaña "2. Verificar carta"**
1. Sube el documento a verificar.
2. Sube (o pega) la `constancia.json` correspondiente.
3. Clic en "Verificar firma".
4. El sistema recalcula H1 = SHA-256(documento subido), verifica la firma RSA contra el certificado del emisor incluido en la constancia, verifica la firma del sello de tiempo contra el certificado de la TSA, y muestra:
   - Badge verde **APROBADA** si todo coincide.
   - Badge rojo **RECHAZADA** si el documento fue alterado o la firma no corresponde.

---


## 4. Prueba manual con `curl` (equivalente a usar la interfaz web)

Con el servidor corriendo (`python app.py`) en otra terminal:

```bash
# 1) Emitir
curl -s -X POST http://127.0.0.1:5000/emitir \
  -F "firmante=Juan Perez Notario" \
  -F "texto=Yo, Juan Perez, declaro bajo protesta de decir verdad que..." \
  | python3 -m json.tool > respuesta_emision.json

# Extraer la constancia y el documento a archivos individuales
python3 -c "
import json, base64
d = json.load(open('respuesta_emision.json'))
json.dump(d['constancia'], open('constancia.json','w'))
open('documento.txt','wb').write(base64.b64decode(d['documento_base64']))
"

# 2) Verificar (caso válido)
curl -s -X POST http://127.0.0.1:5000/verificar \
  -F "documento=@documento.txt" \
  -F "constancia=@constancia.json" | python3 -m json.tool

# 3) Alterar UN carácter y volver a verificar (debe salir RECHAZADA)
sed -i 's/Yo, Juan/Yo, Xuan/' documento.txt
curl -s -X POST http://127.0.0.1:5000/verificar \
  -F "documento=@documento.txt" \
  -F "constancia=@constancia.json" | python3 -m json.tool
```

---

## 5. aclaraciones

| Componente | Estado |
|---|---|
| RSA-2048 + SHA-256, firma/verificación matemática | Real (librería `cryptography` / OpenSSL) |
| Certificados X.509 autofirmados | Real, campos de vigencia genuinos |
| Hash SHA-256 e integridad byte a byte | Real |
| Verificación binaria H1 vs H2 | Real |
| Sello de tiempo firmado (vínculo documento ↔ instante) | Real criptográficamente, pero la "TSA" vive en el mismo servidor (identidad separada, mismo esquema RSA-SHA256) en lugar de ser un tercero acreditado externo (RFC 3161 real requeriría contratar una TSA acreditada, p.ej. bajo eIDAS o la PKI nacional correspondiente) |
| Estado de certificado ("GOOD/VIGENTE") | Calculado sobre fechas reales del certificado (`not_before`/`not_after`); no hay CA raíz ni OCSP real porque los certificados son autofirmados |

**NOTA: ESTE PROYECTO NO TIENE VALIDEZ LEGAL Y/O NOTARIAL. HECHO CON FINES EDUCATIVOS.**


--- 

## Creadores involucrados
- 
- Beatriz Carrillo
-
-
-

