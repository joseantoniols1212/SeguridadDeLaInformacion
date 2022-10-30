import socket_class
import json
import funciones_rsa
import funciones_aes

# Cargamos las claves
Kpub_A = funciones_rsa.cargar_RSAKey_Publica("rsa_alice.pub")
Kpri_B = funciones_rsa.cargar_RSAKey_Privada("rsa_bob.pem", "bob")

# Creamos socket y escuchamos
socketserver = socket_class.SOCKET_SIMPLE_TCP("127.0.0.1", 8081)
print("Bob: Esperando a Alice...")
socketserver.escuchar()

array_bytes = socketserver.recibir()

msg = json.loads(array_bytes.decode("utf8"))

cifradoK1, cifradoK2, firma = msg

K1 = funciones_rsa.descifrarRSA_OAEP_BIN(bytearray.fromhex(cifradoK1), Kpri_B)
K2 = funciones_rsa.descifrarRSA_OAEP_BIN(bytearray.fromhex(cifradoK2), Kpri_B)
firma = bytearray.fromhex(firma)

comprobacion_firma = funciones_rsa.comprobarRSA_PSS(
        K1+K2,
        firma,
        Kpub_A)

if comprobacion_firma:
    print("Bob: Firma valida. Comunicacion establecida.")
else:
    raise Exception("Error en la firma.")


array_bytes = socketserver.recibir()

aes_decipher = funciones_aes.iniciarAES_GCM_descifrado(K1, )
encripted_msg, hmac = json.loads(array_bytes.decode("utf8"))


socketserver.cerrar()


# socketclient = socket_class.SOCKET_SIMPLE_TCP("127.0.0.1",8080)
# socketclient.conectar()
# socketclient.enviar(json.dumps(["Hola alice"]).encode("utf-8"))
# array_bytes = socketclient.recibir()
# msg = json.loads(array_bytes.decode("utf-8"))
# print(msg)
# socketclient.cerrar()
