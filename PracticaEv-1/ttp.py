import socket_class
import json
import funciones_rsa
import funciones_aes

# Creamos la clave privada 
Kpriv_T = funciones_rsa.crear_RSAKey()
funciones_rsa.guardar_RSAKey_Publica("rsa_ttp.pub", Kpriv_T, "ttp")

# Creamos socket y escuchamos
socketserver = socket_class.SOCKET_SIMPLE_TCP("127.0.0.1", 8080)
print("TTP: Escuchando...")
socketserver.escuchar()


