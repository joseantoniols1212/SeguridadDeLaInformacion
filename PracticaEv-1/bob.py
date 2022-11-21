import socket_class
import funciones_rsa
import funciones_aes
import funciones_protocolo
import json
import sys


# Creamos la clave privada y compartimos la publica en un fichero
Kpri_B = funciones_rsa.crear_RSAKey()
funciones_rsa.guardar_RSAKey_Publica("rsa_bob.pub", Kpri_B)

# Creamos la clave simetrica KBT
KBT = funciones_aes.crear_AESKey()

# Creamos socket y conectamos con TTP
socket = socket_class.SOCKET_SIMPLE_TCP("127.0.0.1", 8081)
print("Bob a TTP: Iniciando comunicacion...")
socket.conectar()

# Cargamos la clave publica de TTP
Kpub_T = funciones_rsa.cargar_RSAKey_Publica("rsa_ttp.pub")


# 2. B -> T : Bob contacta con TTP

funciones_protocolo.iniciar_sesion("Bob", KBT, Kpri_B, Kpub_T, socket)

socket.cerrar()


# 5. A -> B : Alice reenvia mensaje de TTP a Bob e inicia comunicacion con Bob

# Creamos socket para escuchar a Alice
socket = socket_class.SOCKET_SIMPLE_TCP("127.0.0.1", 8082)
print("Bob a TTP: Escuchando ...")
socket.escuchar()

msg = socket.recibir().decode("utf-8")
nonceT, macT, msg_cifrado_T, nonceA, macA, msg_cifrado_A = json.loads(msg)
nonceT = bytearray.fromhex(nonceT)
macT = bytearray.fromhex(macT)
msg_cifrado_T = bytearray.fromhex(msg_cifrado_T)
nonceA = bytearray.fromhex(nonceA)
macA = bytearray.fromhex(macA)
msg_cifrado_A = bytearray.fromhex(msg_cifrado_A)

# Iniciamos motor de desencriptado aes para los mensajes de T
aes_decrypt_T = funciones_aes.iniciarAES_GCM_descifrado(KBT, nonceT)

# Decoficamos el mensaje de T para obtener la clave KAB
msg = funciones_aes.descifrarAES_GCM(aes_decrypt_T, msg_cifrado_T, macT)
if not msg:
    raise Exception("Bob: Error en la autenticacion (paso 5, decodificando mensaje de T)")
timestamp_T, KAB = json.loads(msg)
KAB = bytearray.fromhex(KAB)

# Iniciamos motor de desencriptado aes para los mensajes de A
aes_decrypt_A = funciones_aes.iniciarAES_GCM_descifrado(KAB, nonceA)

# Decodificamos el mensaje de A y comprobamos que coinciden los timestamp
msg = funciones_aes.descifrarAES_GCM(aes_decrypt_A, msg_cifrado_A, macA)
if not msg:
    raise Exception("Bob: Error en la autenticacion (paso 5, decodificando mensaje de A)")
nombre, timestamp_A = json.loads(msg)


# 6. B -> A : Bob confirma inicio de comunicaciones con Alice

# Iniciamos motor de encriptado aes para los mensajes de A
aes_encrypt, nonce = funciones_aes.iniciarAES_GCM_cifrado(KAB)

new_timestamp = timestamp_A+1
msg_cifrado, mac = funciones_aes.cifrarAES_GCM(
        aes_encrypt, new_timestamp.to_bytes(32, sys.byteorder))
msg_json = json.dumps([nonce.hex(), mac.hex(), msg_cifrado.hex()])
socket.enviar(msg_json.encode("utf-8"))
print("Bob -> Alice (descifrado):", new_timestamp)


# 7. A -> B : Alice le manda el DNI a Bob

msg_recibido = socket.recibir().decode("utf-8")
nonce, mac, msg_cifrado = json.loads(msg_recibido)
nonce = bytearray.fromhex(nonce)
mac = bytearray.fromhex(mac)
msg_cifrado = bytearray.fromhex(msg_cifrado)

# Iniciamos motor de desencriptado aes para los mensajes de A
aes_decrypt = funciones_aes.iniciarAES_GCM_descifrado(KAB, nonce)

dni_bytes = funciones_aes.descifrarAES_GCM(aes_decrypt, msg_cifrado, mac)
if not dni_bytes:
    raise Exception("Bob: Error en la autenticacion (paso 7)")
print("Bob ha recibido el mensaje con el dni: ", dni_bytes.decode("utf-8"))


# 8. B -> A : Bob le manda el apellido a Alice

# Iniciamos motor de encriptado aes para los mensajes de A
aes_encrypt, nonce = funciones_aes.iniciarAES_GCM_cifrado(KAB)

msg_cifrado, mac = funciones_aes.cifrarAES_GCM(
        aes_encrypt,
        "Luque".encode("utf-8"))
print("Bob -> Alice (descifrado): Luque")

msg_json = json.dumps([nonce.hex(), mac.hex(), msg_cifrado.hex()])
socket.enviar(msg_json.encode("utf-8"))
