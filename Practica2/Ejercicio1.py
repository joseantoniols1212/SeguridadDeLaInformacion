from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad

key = get_random_bytes(16)
IV = get_random_bytes(16)  # IV aleatorio de 64 bits
BLOCK_SIZE_AES = 16 # Bloque de 64 bits
msg1 = "Hola amigas de la seguridad".encode("utf-8")
msg2 = "Hola amigos de la seguridad".encode("utf-8")

cypher = AES.new(key, AES.MODE_CBC, IV)

cyphertext1 = cypher.encrypt(pad(msg1, BLOCK_SIZE_AES))
cyphertext2 = cypher.encrypt(pad(msg2, BLOCK_SIZE_AES))

print("Primer mensaje", cyphertext1)
print("Segundo mensaje", cyphertext2)

decypher = AES.new(key, AES.MODE_CBC, IV)

new_msg1=unpad(decypher.decrypt(cyphertext1),BLOCK_SIZE_AES).decode("utf-8", "ignore")
new_msg2=unpad(decypher.decrypt(cyphertext2),BLOCK_SIZE_AES).decode("utf-8", "ignore")

print("Primer mensaje", new_msg1)
print("Segundo mensaje", new_msg2)
