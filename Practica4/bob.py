import socket_class
import json
import funciones_rsa
import funciones_aes

Kpub_A = funciones_rsa.cargar_RSAKey_Publica("rsa_alice.pub")
Kpri_B = funciones_rsa.cargar_RSAKey_Privada("rsa_bob.pem","bob")

socketserver = socket_class.SOCKET_SIMPLE_TCP("127.0.0.1",8081)
socketserver.escuchar()

array_bytes = socketserver.recibir()

msg = json.loads(array_bytes.decode("utf-8"))

cifradoK1, cifradoK2, firma = msg

comprobacion_firma = funciones_rsa.comprobarRSA_PSS(json.dumps([cifradoK1.hex(),cifradoK2.hex()]).encode("utf-8"), firma, Kpub_A) # Falta comprobar firma

K1 = funciones_rsa.descifrarRSA_OAEP_BIN(cifradoK1, Kpri_B)
K2 = funciones_rsa.descifrarRSA_OAEP_BIN(cifradoK2, Kpri_B)

socketserver.enviar(b"Recibido configuracion")

socketserver.cerrar()


# socketclient = socket_class.SOCKET_SIMPLE_TCP("127.0.0.1",8080)
# socketclient.conectar()
# socketclient.enviar(json.dumps(["Hola alice"]).encode("utf-8"))
# array_bytes = socketclient.recibir()
# msg = json.loads(array_bytes.decode("utf-8"))
# print(msg)
# socketclient.cerrar()
