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
socketclient = socket_class.SOCKET_SIMPLE_TCP("127.0.0.1", 8081)
print("Alice: Iniciando comunicacion...")
socketclient.conectar()

# 1. A -> B : Intercambio de claves simetricas

cifradoK1 = funciones_rsa.cifrarRSA_OAEP_BIN(K1, Kpub_B)
cifradoK2 = funciones_rsa.cifrarRSA_OAEP_BIN(K2, Kpub_B)

firma = funciones_rsa.firmarRSA_PSS(
        K1+K2,
        Kpri_A)

payload = json.dumps([
            cifradoK1.hex(),
            cifradoK2.hex(),
            firma.hex()])

socketclient.enviar(payload.encode("utf8"))

# 2. A -> B : Establecimiento de conexion simetrica
aes_cipher, nonce_alice = funciones_aes.iniciarAES_GCM_cifrado(K1)
msg = [b"Alice", nonce_alice]
h = HMAC.new(K2, msg, digestmod=SHA256)
msg_cifrado = aes_cipher.encrypt(json.dumps(msg).encode("utf8"))
payload = json.dumps([msg_cifrado, h.hexdigest()]).encode("utf8")
socketclient.enviar(payload)

socketclient.cerrar()


# socketserver = socket_class.SOCKET_SIMPLE_TCP("127.0.0.1",8080)
# socketserver.escuchar()
#
# array_bytes = socketserver.recibir()
# msg = json.loads(array_bytes.decode("utf-8"))
# print(msg)
# socketserver.enviar("Comunicacion finalizada".encode("utf-8"))
# socketserver.cerrar()
