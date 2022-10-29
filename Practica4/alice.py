import socket_class
import funciones_rsa
import funciones_aes
import json

Kpub_B = funciones_rsa.cargar_RSAKey_Publica("rsa_bob.pub")
Kpri_A = funciones_rsa.cargar_RSAKey_Privada("rsa_alice.pem","alice")

K1 = funciones_aes.crear_AESKey()
K2 = funciones_aes.crear_AESKey()

socketclient = socket_class.SOCKET_SIMPLE_TCP("127.0.0.1",8081)
socketclient.conectar()

cifradoK1 = funciones_rsa.cifrarRSA_OAEP_BIN(K1, Kpub_B)
cifradoK2 = funciones_rsa.cifrarRSA_OAEP_BIN(K2, Kpub_B)

firma = funciones_rsa.firmarRSA_PSS(json.dumps([cifradoK1.hex(),cifradoK2.hex()]).encode("utf-8"), Kpri_A)

socketclient.enviar(json.dumps([cifradoK1, cifradoK2, firma]).encode("utf-8"))

array_bytes = socketclient.recibir()

print(array_bytes)

socketclient.cerrar()



# socketserver = socket_class.SOCKET_SIMPLE_TCP("127.0.0.1",8080)
# socketserver.escuchar()
#
# array_bytes = socketserver.recibir()
# msg = json.loads(array_bytes.decode("utf-8"))
# print(msg)
# socketserver.enviar("Comunicacion finalizada".encode("utf-8"))
# socketserver.cerrar()

