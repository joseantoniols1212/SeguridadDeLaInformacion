n = 3

def cifradoCesarAlfabetoInglesMAY(cadena):
    """Devuelve un cifrado Cesar tradicional (+n)"""
    # Definir la nueva cadena resultado
    resultado = ''
    # Realizar el "cifrado", sabiendo que A = 65, Z = 90, a = 97, z = 122
    i = 0
    while i < len(cadena):
        # Recoge el caracter a cifrar
        ordenClaro = ord(cadena[i])
        ordenCifrado = 0
        # Cambia el caracter a cifrar
        if (ordenClaro >= 65 and ordenClaro <= 90):
            ordenCifrado = (((ordenClaro - 65) + n) % 26) + 65
        if (ordenClaro >= 97 and ordenClaro <= 122):
            ordenCifrado = (((ordenClaro - 97) + n) % 26) + 97
        # Añade el caracter cifrado al resultado
        resultado = resultado + chr(ordenCifrado)
        i = i + 1
    # devuelve el resultado
    return resultado

def descifradoCesarAlfabetoInglesMAY(cadena):
    """ Devuelve un descifrado de Cesar (+n) """
    resultado = ""
    # Realizar el "descifrado", sabiendo que A = 65, Z = 90, a = 97, z = 122
    i = 0
    while i < len(cadena):
        # Recoge el caracter a descifrar
        ordenCifrado = ord(cadena[i])
        ordenClaro = 0
        # Cambia el caracter a descifrar
        if (ordenCifrado >= 65 and ordenCifrado <= 90):
            ordenClaro = (((ordenCifrado - 65) - n) % 26) + 65
        if (ordenCifrado >= 97 and ordenCifrado <= 122):
            ordenClaro = (((ordenCifrado - 97) - n) % 26) + 97
        # Añade el caracter descifrado al resultado
        resultado = resultado + chr(ordenClaro)
        i = i + 1
    # devuelve el resultado
    return resultado

claroCESAR = 'veni vidi vinci zeta'
print(claroCESAR)
cifradoCESAR = cifradoCesarAlfabetoInglesMAY(claroCESAR) 
print(cifradoCESAR)
desdifradoCESAR = descifradoCesarAlfabetoInglesMAY(cifradoCESAR)
print(desdifradoCESAR)
