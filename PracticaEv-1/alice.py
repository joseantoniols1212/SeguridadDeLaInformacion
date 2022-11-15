import socket_class
import json
import funciones_rsa
import funciones_aes

# Cargamos la clave publica de TTP
Kpri_T = funciones_rsa.cargar_RSAKey_Privada("rsa_ttp.pem", "ttp")

# Creamos la clave simetrica K_TA
KAT = funciones_aes.crear_AESKey()

# Creamos socket y conectamos con TTP
socketclient = socket_class.SOCKET_SIMPLE_TCP("127.0.0.1", 8080)
print("Alice a TTP: Iniciando comunicacion...")
socketclient.conectar()


# 1. A -> T : Alice se registra ante el TTP

msg1 = jso
