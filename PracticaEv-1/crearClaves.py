import funciones_rsa

password_ttp = "ttp"
fichero_ttp = "rsa_ttp"

# Crear una clave pública y una clave privada RSA de 2048 bits para TTP. Guardar cada clave en un fichero. 
key = funciones_rsa.crear_RSAKey()
funciones_rsa.guardar_RSAKey_Privada(fichero_ttp + ".pem", key, password_ttp)
funciones_rsa.guardar_RSAKey_Publica(fichero_ttp + ".pub", key)
