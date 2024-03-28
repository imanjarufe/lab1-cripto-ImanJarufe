import string
import sys

def cifrar_cesar(texto , corrimiento):
    texto_cifrado = ''
    for caracter in texto:
        if caracter.islower(): 
            codigo = ord(caracter) # Obtiene el código ASCII del carácter.
            codigo_cifrado = (codigo - 97 + corrimiento) % 26 + 97 #Aplicar el corrimiento ajustado para que este dentro del rango de letras minúsculas ASCII
            caracter_cifrado = chr(codigo_cifrado)  #Convierte el código ASCII cifrado de nuevo a un carácter.
            texto_cifrado += caracter_cifrado
        else:
            texto_cifrado += caracter  #Mantiene los caracteres que no son letras minúsculas sin cifrar
    return texto_cifrado

texto_original = sys.argv[1]
corrimiento = int(sys.argv[2])

texto_cifrado = cifrar_cesar(texto_original, corrimiento) #llama a la función para cifrar el texto.
print(texto_cifrado) #imprime el texto cifrado

