from Crypto.Hash import SHA256, HMAC
import base64
import json
import sys
from socket_class import SOCKET_SIMPLE_TCP
import funciones_aes
from Crypto.Random import get_random_bytes

# Paso 0: Inicializacion
########################

# Lee clave KBT
KBT = open("KBT.bin", "rb").read()

# Paso 1) B->T: KBT(Bob, Nb) en AES-GCM
#######################################

# Crear el socket de conexion con T (5551)
print("Creando conexion con T...")
socket = SOCKET_SIMPLE_TCP('127.0.0.1', 5551)
socket.conectar()

# Crea los campos del mensaje
t_n_origen = get_random_bytes(16)

# Codifica el contenido (los campos binarios en una cadena)
# y contruyo el mensaje JSON
msg_TE = []
msg_TE.append("Bob")
msg_TE.append(t_n_origen.hex())
json_ET = json.dumps(msg_TE)
print("Bob: B -> T (descifrado): " + json_ET)

# Cifra los datos con AES GCM
aes_engine = funciones_aes.iniciarAES_GCM(KBT)
cifrado, cifrado_mac, cifrado_nonce = funciones_aes.cifrarAES_GCM(
        aes_engine,
        json_ET.encode("utf-8"))

# Envia los datos
socket.enviar(json.dumps({
    "cifrado": cifrado.hex(),
    "cifrado_mac": cifrado_mac.hex(),
    "cifrado_nonce": cifrado_nonce.hex()
    }).encode("utf-8"))

# Paso 2) T->B: KBT(K1, K2, Nb) en AES-GCM
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
print("Bob: T -> B (descifrado): " + json_msg)
msg = json.loads(json_msg)

K1, K2, t_n_destino = msg
t_n_destino = bytearray.fromhex(t_n_destino)
K1 = bytearray.fromhex(K1)
K2 = bytearray.fromhex(K2)

# Comprobamos el Nb
if t_n_destino != t_n_origen:
    raise Exception("Nb no coincide (paso 2)")

# Cerramos el socket entre B y T, no lo utilizaremos mas
socket.cerrar()

# Paso 5) A->B: KAB(Nombre) en AES-CTR con HMAC
###############################################

# Crear el socket de conexion con A (8080)
print("Creando conexion con A...")
socket = SOCKET_SIMPLE_TCP('127.0.0.1', 8080)
socket.escuchar()

# Recibimos mensaje
json_msg = socket.recibir().decode("utf-8")

# Destructuramos y convertimos desde hex
msg_cifrado, mac, nonce = json.loads(json_msg).values()
msg_cifrado = bytearray.fromhex(msg_cifrado)
print("Nonce: "+nonce)
nonce = bytearray.fromhex(nonce)

# Inicializamos decipher y hmac
decipher = funciones_aes.iniciarAES_CTR_descifrado(K1, nonce)
h = HMAC.new(K2, digestmod=SHA256)

# Desciframos
msg = funciones_aes.descifrarAES_CTR(decipher, msg_cifrado)

# Comprobamos mac
h.update(msg)
if mac != h.hexdigest():
    raise Exception("ALERTA. Mac incorrecta (paso 5).")

msg = msg.decode("utf-8")
print("Bob: A -> B (descifrado): " + msg)

# Paso 6) B->A: KAB(Apellido) en AES-CTR con HMAC
#################################################



# Paso 7) A->B: KAB(END) en AES-CTR con HMAC
############################################

# (A realizar por el alumno/a...)
