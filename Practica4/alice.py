import socket_class
from Crypto.Hash import HMAC, SHA256
import funciones_rsa
import funciones_aes
import json

# Cargamos las claves
Kpub_B = funciones_rsa.cargar_RSAKey_Publica("rsa_bob.pub")
Kpri_A = funciones_rsa.cargar_RSAKey_Privada("rsa_alice.pem", "alice")

# Creamos las claves simetricas
K1 = funciones_aes.crear_AESKey()
K2 = funciones_aes.crear_AESKey()

# Creamos socket y conectamos
socketclient = socket_class.SOCKET_SIMPLE_TCP("127.0.0.1", 8080)
print("Alice: Iniciando comunicacion...")
socketclient.conectar()

# 1. A -> B : Intercambio de claves simetricas

cifradoK1 = funciones_rsa.cifrarRSA_OAEP_BIN(K1, Kpub_B)
cifradoK2 = funciones_rsa.cifrarRSA_OAEP_BIN(K2, Kpub_B)

firma = funciones_rsa.firmarRSA_PSS(
        K1+K2,
        Kpri_A)

json_msg = json.dumps({
    "clave1": cifradoK1.hex(),
    "clave2": cifradoK2.hex(),
    "firma": firma.hex()
})

socketclient.enviar(json_msg.encode("utf8"))

# Creamos clase cifrado AES CTR y HMAC
cipher, nonce_alice = funciones_aes.iniciarAES_CTR_cifrado(K1)
h = HMAC.new(K2, digestmod=SHA256)

# 2. A -> B : Establecimiento de conexion simetrica
body = json.dumps(["Alice"])
h.update(body.encode("utf8"))
json_msg = json.dumps({
    "body": funciones_aes.cifrarAES_CTR(cipher, body.encode("utf8")).hex(),
    "nonce": nonce_alice.hex(),
    "mac": h.hexdigest()
})

print("Alice: Enviado "+body+".")
socketclient.enviar(json_msg.encode("utf8"))


# 3. B -> A : Recibimos confirmacion inicio de conexion simetrica

msg = socketclient.recibir().decode("utf8")

encrypted_body, nonce, mac = json.loads(msg).values()

# Convertimos hex a bytes
nonce = bytearray.fromhex(nonce)
encrypted_body = bytearray.fromhex(encrypted_body)

# Creamos clase descifrado AES CTR
decipher = funciones_aes.iniciarAES_CTR_descifrado(K1, nonce)

body = funciones_aes.descifrarAES_CTR(decipher, encrypted_body)

# Comprobamos mac
h.update(body)
if mac != h.hexdigest():
    raise Exception("Error en mac")

body = body.decode("utf8")

print("Alice: recibido "+body+".")

body = json.loads(body)
if body != ["Alice", "Bob"]:
    raise Exception("Error en la confirmacion de comunicacion simetrica")
else:
    print("Handshake finalizado")


# 4. A -> B : Mensaje "hola amigos"
body = "Hola Amigos"
h.update(body.encode("utf8"))
json_msg = json.dumps({
    "body": funciones_aes.cifrarAES_CTR(cipher, body.encode("utf8")).hex(),
    "mac": h.hexdigest()
})

print("Alice: Enviado "+body+".")

socketclient.enviar(json_msg.encode("utf8"))


# 5. B -> A : Recibimos mensaje

msg = socketclient.recibir().decode("utf8")

encrypted_body, mac = json.loads(msg).values()

encrypted_body = bytearray.fromhex(encrypted_body)
body = funciones_aes.descifrarAES_CTR(decipher, encrypted_body)

# Comprobamos mac y nonce
h.update(body)
if mac != h.hexdigest():
    raise Exception("Error en mac")

body = body.decode("utf8")  # json

print("Alice: recibido "+body+".")

socketclient.cerrar()
