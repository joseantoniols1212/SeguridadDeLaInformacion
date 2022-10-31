import socket_class
import json
import funciones_rsa
import funciones_aes
from Crypto.Hash import HMAC, SHA256

# Cargamos las claves
Kpub_A = funciones_rsa.cargar_RSAKey_Publica("rsa_alice.pub")
Kpri_B = funciones_rsa.cargar_RSAKey_Privada("rsa_bob.pem", "bob")

# Creamos socket y escuchamos
socketserver = socket_class.SOCKET_SIMPLE_TCP("127.0.0.1", 8080)
print("Bob: Esperando a Alice...")
socketserver.escuchar()

# 1. A -> B : Recibimos configuracion cifrado simetrico
msg = socketserver.recibir().decode()

cifradoK1, cifradoK2, firma = json.loads(msg).values()

K1 = funciones_rsa.descifrarRSA_OAEP_BIN(bytearray.fromhex(cifradoK1), Kpri_B)
K2 = funciones_rsa.descifrarRSA_OAEP_BIN(bytearray.fromhex(cifradoK2), Kpri_B)
firma = bytearray.fromhex(firma)

if funciones_rsa.comprobarRSA_PSS(K1+K2, firma, Kpub_A):
    print("Bob: Firma valida. Comunicacion establecida.")
else:
    raise Exception("Error en la firma.")

# 2. A -> B : Recibimos mensaje inicio de conexion simetrica

msg = socketserver.recibir().decode("utf8")

encrypted_body, nonce_alice, mac = json.loads(msg).values()

nonce_alice = bytearray.fromhex(nonce_alice)
encrypted_body = bytearray.fromhex(encrypted_body)

# Creamos decipher AES CTR y HMAC
decipher = funciones_aes.iniciarAES_CTR_descifrado(K1, nonce_alice)
h = HMAC.new(K2, digestmod=SHA256)

body = funciones_aes.descifrarAES_CTR(decipher, encrypted_body)

# Comprobamos mac y nonce
h.update(body)
if mac != h.hexdigest():
    raise Exception("Error en mac")

body = body.decode("utf8")  # json

print("Bob: recibido "+body+".")


# 3. B -> A : Confirmamos inicio de conexion simetrica

# Creamos cipher AES CTR
cipher, nonce_bob = funciones_aes.iniciarAES_CTR_cifrado(K1)

# Añadimos nombre de bob al cuerpo del mensaje
body = json.loads(body)  # array
body.append("Bob")

body = json.dumps(body)
h.update(body.encode("utf8"))
json_msg = json.dumps({
    "body": funciones_aes.cifrarAES_CTR(cipher, body.encode("utf8")).hex(),
    "nonce": nonce_bob.hex(),
    "mac": h.hexdigest()
    })


print("Bob: Enviado "+body+".")
socketserver.enviar(json_msg.encode("utf8"))


# 4. A -> B : Recibimos mensaje
msg = socketserver.recibir().decode("utf8")

encrypted_body, mac = json.loads(msg).values()

encrypted_body = bytearray.fromhex(encrypted_body)
body = funciones_aes.descifrarAES_CTR(decipher, encrypted_body)

# Comprobamos mac y nonce
h.update(body)
if mac != h.hexdigest():
    raise Exception("Error en mac")

body = body.decode("utf8")  # json

print("Bob: recibido "+body+".")


# 5. B -> A : Mensaje "hola amigas"


body = "Hola Amigas"
h.update(body.encode("utf8"))
json_msg = json.dumps({
    "body": funciones_aes.cifrarAES_CTR(cipher, body.encode("utf8")).hex(),
    "mac": h.hexdigest()
})

print("Bob: Enviado "+body+".")

socketserver.enviar(json_msg.encode("utf8"))

socketserver.cerrar()
