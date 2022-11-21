from Crypto.Hash import SHA256, HMAC
import base64
import json
import sys
from socket_class import SOCKET_SIMPLE_TCP
import funciones_aes

# Paso 0: Crea las claves que T comparte con B y A
##################################################

# Crear Clave KAT, guardar a fichero
KAT = funciones_aes.crear_AESKey()
FAT = open("KAT.bin", "wb")
FAT.write(KAT)
FAT.close()

# Crear Clave KBT, guardar a fichero
KBT = funciones_aes.crear_AESKey()
FBT = open("KBT.bin", "wb")
FBT.write(KBT)
FBT.close()

# Paso 1) B->T: KBT(Bob, Nb) en AES-GCM
#######################################

# Crear el socket de escucha de Bob (5551)
print("Esperando a Bob...")
socket_Bob = SOCKET_SIMPLE_TCP('127.0.0.1', 5551)
socket_Bob.escuchar()

# Crea la respuesta para B y A: K1 y K2
K1 = funciones_aes.crear_AESKey()
K2 = funciones_aes.crear_AESKey()

# Recibe el mensaje
json_recibido = socket_Bob.recibir().decode("utf-8")
cifrado, cifrado_mac, cifrado_nonce = json.loads(json_recibido).values()
cifrado = bytearray.fromhex(cifrado)
cifrado_mac = bytearray.fromhex(cifrado_mac)
cifrado_nonce = bytearray.fromhex(cifrado_nonce)

# Descifro los datos con AES GCM
datos_descifrado_ET = funciones_aes.descifrarAES_GCM(
        KBT,
        cifrado_nonce,
        cifrado,
        cifrado_mac)

# Decodifica el contenido: Bob, Nb
json_ET = datos_descifrado_ET.decode("utf-8", "ignore")
print("Trent: B -> T (descifrado): " + json_ET)
msg_ET = json.loads(json_ET)

# Extraigo el contenido
t_bob, t_nb = msg_ET
t_nb = bytearray.fromhex(t_nb)

# Paso 2) T->B: KBT(K1, K2, Nb) en AES-GCM
##########################################

# Creamos mensaje con los campos necesarios
msg_B = [K1.hex(), K2.hex(), t_nb.hex()]
json_B = json.dumps(msg_B)
print("Trent: T -> B (descifrado): "+json_B)

# Ciframos los datos con AES GCM
aes_engine = funciones_aes.iniciarAES_GCM(KBT)
cifrado, cifrado_mac, cifrado_nonce = funciones_aes.cifrarAES_GCM(
        aes_engine,
        json_B.encode("utf-8"))

# Enviamos los datos
socket_Bob.enviar(json.dumps({
    "cifrado": cifrado.hex(),
    "cifrado_mac": cifrado_mac.hex(),
    "cifrado_nonce": cifrado_nonce.hex()
    }).encode("utf-8"))

# Cerramos el socket entre B y T, no lo utilizaremos mas
socket_Bob.cerrar()

# Paso 3) A->T: KAT(Alice, Na) en AES-GCM
#########################################

# Crear el socket de conexion con T (5552)
print("Creando conexion con T...")
socket_Alice = SOCKET_SIMPLE_TCP('127.0.0.1', 5552)
socket_Alice.escuchar()

# Recibe el mensaje
json_recibido = socket_Alice.recibir().decode("utf-8")
cifrado, cifrado_mac, cifrado_nonce = json.loads(json_recibido).values()
cifrado = bytearray.fromhex(cifrado)
cifrado_mac = bytearray.fromhex(cifrado_mac)
cifrado_nonce = bytearray.fromhex(cifrado_nonce)

# Descifro los datos con AES GCM
datos_descifrado = funciones_aes.descifrarAES_GCM(
        KAT,
        cifrado_nonce,
        cifrado,
        cifrado_mac)

# Decodifica el contenido: Alice, Na
json_msg = datos_descifrado.decode("utf-8", "ignore")
print("Trent: A -> T (descifrado): " + json_msg)
msg = json.loads(json_msg)

# Extraigo el contenido
t_alice, t_na = msg
t_na = bytearray.fromhex(t_na)


# Paso 4) T->A: KAT(K1, K2, Na) en AES-GCM
##########################################

# Creamos mensaje con los campos necesarios
msg = [K1.hex(), K2.hex(), t_na.hex()]
json_msg = json.dumps(msg)
print("Trent: T -> A (descifrado): "+json_B)

# Ciframos los datos con AES GCM
aes_engine = funciones_aes.iniciarAES_GCM(KAT)
cifrado, cifrado_mac, cifrado_nonce = funciones_aes.cifrarAES_GCM(
        aes_engine,
        json_msg.encode("utf-8"))

# Enviamos los datos
socket_Alice.enviar(json.dumps({
    "cifrado": cifrado.hex(),
    "cifrado_mac": cifrado_mac.hex(),
    "cifrado_nonce": cifrado_nonce.hex()
    }).encode("utf-8"))

# Cerramos el socket entre A y T, no lo utilizaremos mas
socket_Alice.cerrar()
