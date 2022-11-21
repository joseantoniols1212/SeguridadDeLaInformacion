import funciones_rsa

password_ttp = "ttp"
fichero_ttp = "rsa_ttp"

password_alice = "alice"
fichero_alice = "rsa_alice"

password_bob = "bob"
fichero_bob = "rsa_bob"

# Crear una clave pública y una clave privada RSA de 2048 bits para TTP. Guardar cada clave en un fichero.
key = funciones_rsa.crear_RSAKey()
funciones_rsa.guardar_RSAKey_Privada(fichero_ttp + ".pem", key, password_ttp)
funciones_rsa.guardar_RSAKey_Publica(fichero_ttp + ".pub", key)

key = funciones_rsa.crear_RSAKey()
funciones_rsa.guardar_RSAKey_Privada(fichero_alice + ".pem", key, password_alice)
funciones_rsa.guardar_RSAKey_Publica(fichero_alice + ".pub", key)

key = funciones_rsa.crear_RSAKey()
funciones_rsa.guardar_RSAKey_Privada(fichero_bob + ".pem", key, password_bob)
funciones_rsa.guardar_RSAKey_Publica(fichero_bob + ".pub", key)
