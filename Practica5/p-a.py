from Crypto.Hash import SHA256, HMAC
import base64
import json
import sys
from socket_class import SOCKET_SIMPLE_TCP
import funciones_aes
from Crypto.Random import get_random_bytes

# Paso 0: Inicializacion
########################

# Lee clave KAT
KBT = open("KAT.bin", "rb").read()

# Paso 3) A->T: KAT(Alice, Na) en AES-GCM
#########################################

# Crear el socket de conexion con T (5552)
print("Creando conexion con T...")
socket = SOCKET_SIMPLE_TCP('127.0.0.1', 5552)
socket.conectar()

# Crea los campos del mensaje
na_origen = get_random_bytes(16)

# Codifica el contenido (los campos binarios en una cadena)
# y contruyo el mensaje JSON
msg = []
msg.append("Alice")
msg.append(na_origen.hex())
json_msg = json.dumps(msg)
print("Alice: A -> T (descifrado): " + json_msg)

# Cifra los datos con AES GCM
aes_engine = funciones_aes.iniciarAES_GCM(KBT)
cifrado, cifrado_mac, cifrado_nonce = funciones_aes.cifrarAES_GCM(
        aes_engine,
        json_msg.encode("utf-8"))

# Envia los datos
socket.enviar(json.dumps({
    "cifrado": cifrado.hex(),
    "cifrado_mac": cifrado_mac.hex(),
    "cifrado_nonce": cifrado_nonce.hex()
    }).encode("utf-8"))

# Paso 4) T->A: KAT(K1, K2, Na) en AES-GCM
##########################################

json_recibido = socket.recibir().decode("utf-8")
cifrado, cifrado_mac, cifrado_nonce = json.loads(json_recibido).values()
cifrado = bytearray.fromhex(cifrado)
cifrado_mac = bytearray.fromhex(cifrado_mac)
cifrado_nonce = bytearray.fromhex(cifrado_nonce)

# Descifro los datos con AES GCM
datos_descifrado = funciones_aes.descifrarAES_GCM(
        KBT,
        cifrado_nonce,
        cifrado,
        cifrado_mac)

# Decodifica el contenido: K1, K2, Nb
json_msg = datos_descifrado.decode("utf-8", "ignore")
print("Alice: T -> A (descifrado): " + json_msg)
msg = json.loads(json_msg)

K1, K2, na_destino = msg
na_destino = bytearray.fromhex(na_destino)
K1 = bytearray.fromhex(K1)
K2 = bytearray.fromhex(K2)

# Comprobamos el Na
if na_destino != na_origen:
    raise Exception("Na no coincide (paso 4)")

# Cerramos el socket entre B y T, no lo utilizaremos mas
socket.cerrar()


# Paso 5) A->B: KAB(Nombre) en AES-CTR con HMAC
###############################################

# Crear el socket de conexion con B (8080)
print("Creando conexion con B...")
socket = SOCKET_SIMPLE_TCP('127.0.0.1', 8080)
socket.conectar()

# Incializamos cipher y hmac
cipher, nonce = funciones_aes.iniciarAES_CTR_cifrado(K1)
h = HMAC.new(K2, digestmod=SHA256)

# Creamos mensaje
msg = "Nombre"
print("Alice: A -> B (descifrado): " + msg)
msg = msg.encode("utf-8")
h.update(msg)

# Ciframos
cifrado = funciones_aes.cifrarAES_CTR(cipher, msg)

# Enviamos
socket.enviar(json.dumps({
    "cifrado": cifrado.hex(),
    "cifrado_mac": h.hexdigest(),
    "cifrado_nonce": nonce.hex()
    }).encode("utf-8"))

# Paso 6) B->A: KAB(Apellido) en AES-CTR con HMAC
#################################################

# (A realizar por el alumno/a...)

# Paso 7) A->B: KAB(END) en AES-CTR con HMAC
############################################

# (A realizar por el alumno/a...)
