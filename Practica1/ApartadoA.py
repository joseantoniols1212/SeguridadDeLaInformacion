def cifradoCesarAlfabetoInglesMAY(cadena):
    """Devuelve un cifrado Cesar tradicional (+3)"""
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
            ordenCifrado = (((ordenClaro - 65) + 3) % 26) + 65
        # Añade el caracter cifrado al resultado
        resultado = resultado + chr(ordenCifrado)
        i = i + 1
    # devuelve el resultado
    return resultado

def descifradoCesarAlfabetoInglesMAY(cadena):
    """ Devuelve un descifrado de Cesar (+3) """
    resultado = ""
    # Realizar el "descifrado", sabiendo que A = 65, Z = 90, a = 97, z = 122
    i = 0
    while i < len(cadena):
        # Recoge el caracter a descifrar
        ordenCifrado = ord(cadena[i])
        ordenClaro = 0
        # Cambia el caracter a descifrar
        if (ordenCifrado >= 65 and ordenCifrado <= 90):
            ordenClaro = (((ordenCifrado - 65) - 3) % 26) + 65
        # Añade el caracter descifrado al resultado
        resultado = resultado + chr(ordenClaro)
        i = i + 1
    # devuelve el resultado
    return resultado

claroCESAR = 'VENI VIDI VINCI ZETA'
print(claroCESAR)
cifradoCESAR = cifradoCesarAlfabetoInglesMAY(claroCESAR) 
print(cifradoCESAR)
desdifradoCESAR = descifradoCesarAlfabetoInglesMAY(cifradoCESAR)
print(desdifradoCESAR)
