import json
import funciones_aes

K1 = funciones_aes.crear_AESKey()
K2 = funciones_aes.crear_AESKey()

print(json.dumps([K1.hex(),K2.hex()]))
