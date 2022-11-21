import socket_class
import json
import funciones_rsa
import funciones_aes
import time


# Definimos una variable global donde almacenar usuarios con sus respectivas claves

SESIONES = {}  # Inicializamos diccionario de pares nombre:clave(hexadecimal)

# Definimos funciones que usara ttp


def iniciar_sesion(socket, Kpub_usuario):
    # - Recibimos y desestructuramos el mensaje en sus componentes
    json_recibido = socket.recibir().decode("utf-8")

    msg_cifrado, firma_hex = json.loads(json_recibido)
    firma = bytearray.fromhex(firma_hex)
    msg_cifrado = bytearray.fromhex(msg_cifrado)

    msg_json = funciones_rsa.descifrarRSA_OAEP(msg_cifrado, Kpri_T)
    nombre, clave_sesion = json.loads(msg_json)
    clave_sesion = bytearray.fromhex(clave_sesion)

    # - Comprobamos firma
    if not funciones_rsa.comprobarRSA_PSS(clave_sesion, firma, Kpub_usuario):
        raise Exception("Firma de "+nombre+" no valida al iniciar sesion.")

    # - Incorporamos los datos del usuario a un diccionario
    SESIONES.update({nombre: clave_sesion})


def enviar_clave(socket_emisor, emisor, receptor):
    # Creamos la clave para la comunicacion
    K = funciones_aes.crear_AESKey()

    # Comprobamos que emisor y receptor esten en SESIONES
    if emisor not in SESIONES:
        raise Exception("El emisor"+emisor+" no tiene sesion abierta.")
    if receptor not in SESIONES:
        raise Exception("El receptor"+receptor+" no tiene sesion abierta.")

    # Iniciamos los motores de cifrado
    aes_engine_rec, nonce_rec = funciones_aes.iniciarAES_GCM_cifrado(
            SESIONES.get(receptor))
    aes_engine_emi, nonce_emi = funciones_aes.iniciarAES_GCM_cifrado(
            SESIONES.get(emisor))

    # Construimos el mensaje para el receptor
    timestamp = int(time.time())
    msg_rec = [timestamp, K.hex()]
    json_msg_rec = json.dumps(msg_rec).encode("utf-8")
    cifrado_rec, mac_rec = funciones_aes.cifrarAES_GCM(
            aes_engine_rec,
            json_msg_rec)
    msg_emisor = [
            nonce_rec.hex(), timestamp, K.hex(),
            cifrado_rec.hex(), mac_rec.hex()]
    json_msg_emisor = json.dumps(msg_emisor)
    print("TTP -> "+emisor+" (descifrado): "+json_msg_emisor)
    cifrado_emisor, mac_emi = funciones_aes.cifrarAES_GCM(
            aes_engine_emi,
            json_msg_emisor.encode("utf-8"))

    # Enviamos mensaje
    msg = [nonce_emi.hex(), cifrado_emisor.hex(), mac_emi.hex()]
    socket_emisor.enviar(json.dumps(msg).encode("utf-8"))


# Creamos la clave privada y compartimos la publica en un fichero
Kpri_T = funciones_rsa.crear_RSAKey()
funciones_rsa.guardar_RSAKey_Publica("rsa_ttp.pub", Kpri_T)

# Creamos socket y escuchamos a alice
socket_alice = socket_class.SOCKET_SIMPLE_TCP("127.0.0.1", 8080)
print("TTP a Alice: Escuchando...")
socket_alice.escuchar()

# Creamos socket y escuchamos a bob
socket_bob = socket_class.SOCKET_SIMPLE_TCP("127.0.0.1", 8081)
print("TTP a Bob: Escuchando...")
socket_bob.escuchar()

# Guardamos las claves publicas de alice y bob
Kpub_A = funciones_rsa.cargar_RSAKey_Publica("rsa_alice.pub")
Kpub_B = funciones_rsa.cargar_RSAKey_Publica("rsa_bob.pub")


# 1. A -> T : Alice contacta con TTP

iniciar_sesion(socket_alice, Kpub_A)


# 2. B -> T : Bob contacta con TTP

iniciar_sesion(socket_bob, Kpub_B)


# 3. A -> T : Alice contacta con TTP para obtener KAB

msg = socket_alice.recibir().decode("utf-8")
emisor, receptor = json.loads(msg)


# 4. T -> A : TTP envia la clave para la comunicacion entre A y B

enviar_clave(socket_alice, emisor, receptor)
