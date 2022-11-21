import json
import funciones_rsa


def iniciar_sesion(nombre, Ksesion, Kpriv_usuario, Kpub_ttp, socket):

    # - Construimos mensaje
    msg = []
    msg.append(nombre)
    msg.append(Ksesion.hex())
    json_msg = json.dumps(msg)
    print(nombre+" -> T (descifrado): " + json_msg)

# - Ciframos el mensaje con RSA
    msg_cifrado = funciones_rsa.cifrarRSA_OAEP(json_msg, Kpub_ttp)

# - Firmamos la clave simetrica
    firma = funciones_rsa.firmarRSA_PSS(Ksesion, Kpriv_usuario)

# - Enviamos mensaje
    socket.enviar(json.dumps([msg_cifrado.hex(), firma.hex()]).encode("utf-8"))
