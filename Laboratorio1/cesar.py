import sys

def cifrar_cesar(texto, corrimiento):
    texto_cifrado = ""
    for caracter in texto:
        if caracter.isalpha():
            # Obtener el código ASCII del caracter
            codigo = ord(caracter)
            # Aplicar el corrimiento
            if caracter.islower():
                codigo_cifrado = (codigo - ord('a') + corrimiento) % 26 + ord('a')
            else:
                codigo_cifrado = (codigo - ord('A') + corrimiento) % 26 + ord('A')
            # Convertir el código ASCII cifrado a caracter
            caracter_cifrado = chr(codigo_cifrado)
            texto_cifrado += caracter_cifrado
        else:
            texto_cifrado += caracter
    return texto_cifrado

# Obtener argumentos de la línea de comandos
if len(sys.argv) != 3:
    print("Uso: python3 cesar.py <texto> <corrimiento>")
    sys.exit(1)

texto_original = sys.argv[1]
corrimiento = int(sys.argv[2])

# Cifrar el texto
texto_cifrado = cifrar_cesar(texto_original, corrimiento)
print(texto_cifrado)
