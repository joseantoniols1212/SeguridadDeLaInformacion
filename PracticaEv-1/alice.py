import socket_class
import funciones_rsa
import funciones_aes
import funciones_protocolo
import json
import sys

# Cargamos la clave publica de TTP
Kpub_T = funciones_rsa.cargar_RSAKey_Publica("rsa_ttp.pub")

# Cargamos la privada de Alice
Kpri_A = funciones_rsa.cargar_RSAKey_Privada("rsa_alice.pem", "alice")

# Creamos la clave simetrica KTA
KAT = funciones_aes.crear_AESKey()

# Creamos socket y conectamos con TTP
socket = socket_class.SOCKET_SIMPLE_TCP("127.0.0.1", 8080)
print("Alice a TTP: Iniciando comunicacion...")
socket.conectar()

# 1. A -> T : Alice contacta con TTP

funciones_protocolo.iniciar_sesion("Alice", KAT, Kpri_A, Kpub_T, socket)

# 3. A -> T : Alice contacta con TTP para obtener KAB

socket.enviar(json.dumps(["Alice", "Bob"]).encode("utf-8"))
print("Alice -> T (descifrado): [\"Alice\", \"Bob\"]")

# 4. T -> A : TTP envia la clave para la comunicacion entre A y B

msg_recibido = socket.recibir().decode("utf-8")
nonce, msg_cifrado, mac = json.loads(msg_recibido)
nonce = bytearray.fromhex(nonce)
msg_cifrado = bytearray.fromhex(msg_cifrado)
mac = bytearray.fromhex(mac)

# Iniciamos motor de encriptado
aes_decrypt_T = funciones_aes.iniciarAES_GCM_descifrado(KAT, nonce)

# TODO: terminar ejecucion en caso de que falle autenticidad (msg = FALSE)
msg = funciones_aes.descifrarAES_GCM(aes_decrypt_T, msg_cifrado, mac)

nonceT, timestamp, KAB, msg_cifrado_T_B, macT = json.loads(msg)
KAB = bytearray.fromhex(KAB)

socket.cerrar()

# 5. A -> B : Alice reenvia mensaje de TTP a Bob e inicia comunicacion con Bob

# Creamos socket y conectamos con Bob
socket = socket_class.SOCKET_SIMPLE_TCP("127.0.0.1", 8082)
print("Alice a Bob: Iniciando comunicacion...")
socket.conectar()

# Iniciamos motor de cifrado aes
aes_encrypt, nonceA = funciones_aes.iniciarAES_GCM_cifrado(KAB)

msg_json = json.dumps(["Alice", timestamp])
print("Alice -> B (descifrado): ["+nonceT+", " +
      macT+", "+msg_cifrado_T_B+", "+msg_json+"]")
msg_cifrado_A_B, macA = funciones_aes.cifrarAES_GCM(
        aes_encrypt,
        msg_json.encode("utf-8"))

msg = [nonceT, macT, msg_cifrado_T_B,
       nonceA.hex(), macA.hex(), msg_cifrado_A_B.hex()]
socket.enviar(json.dumps(msg).encode("utf-8"))


# 6. B -> A : Bob confirma inicio de comunicaciones con Alice

msg_recibido = socket.recibir().decode("utf-8")
nonce, mac, msg_cifrado = json.loads(msg_recibido)
nonce = bytearray.fromhex(nonce)
mac = bytearray.fromhex(mac)
msg_cifrado = bytearray.fromhex(msg_cifrado)

# Iniciamos motor de descifrado
aes_decrypt = funciones_aes.iniciarAES_GCM_descifrado(KAB, nonce)

timestamp_bytes = funciones_aes.descifrarAES_GCM(aes_decrypt, msg_cifrado, mac)
timestampB = int.from_bytes(timestamp_bytes, sys.byteorder)

# Comprobamos que se corresponda dicha marca de tiempo
if not timestampB == timestamp+1:
    raise Exception("Error en la marca de tiempo")


# 7. A -> B : Alice le manda el DNI a Bob

# Iniciamos motor de cifrado aes
aes_encrypt, nonce = funciones_aes.iniciarAES_GCM_cifrado(KAB)

msg_cifrado, mac = funciones_aes.cifrarAES_GCM(
        aes_encrypt,
        "77684682C".encode("utf-8"))
print("Alice -> B (descifrado): 77684682C")

msg_json = json.dumps([nonce.hex(), mac.hex(), msg_cifrado.hex()])
socket.enviar(msg_json.encode("utf-8"))


# 8. B -> A : Bob le manda el apellido a Alice

msg_recibido = socket.recibir().decode("utf-8")
nonce, mac, msg_cifrado = json.loads(msg_recibido)
nonce = bytearray.fromhex(nonce)
mac = bytearray.fromhex(mac)
msg_cifrado = bytearray.fromhex(msg_cifrado)

# Iniciamos motor de descifrado
aes_decrypt = funciones_aes.iniciarAES_GCM_descifrado(KAB, nonce)

apellido_bytes = funciones_aes.descifrarAES_GCM(aes_decrypt, msg_cifrado, mac)
print("Alice ha recibido el mensaje con el apellido: ",
      apellido_bytes.decode("utf-8"))
