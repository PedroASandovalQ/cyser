from scapy.all import *
import sys

palabras_espanol = ["el", "en", "de", "es", "un", "una", "que", "por", "para", "con", "del", "lo", "los", "las", "al", "se", "su", "como", "más", "pero", "también", "si", "no"]

def obtener_payloads_icmp(pcap_file):
    payloads = []
    try:
        pkts = rdpcap(pcap_file)
        for pkt in pkts:
            if ICMP in pkt:  # Verificar si el paquete es ICMP
                payload = pkt[ICMP].load
                # Obtener solo el primer valor del campo después del timestamp (8 bytes)
                primer_valor_despues_timestamp = payload[8]
                # Convertir el valor decimal a su carácter ASCII correspondiente y agregarlo a la lista
                simbolo = chr(primer_valor_despues_timestamp)
                payloads.append(simbolo)
    except Exception as e:
        print(f"Error al procesar el archivo pcap: {e}")
    return payloads

def frecuencia_letras(oracion):
    frecuencia = {}
    # Contar la frecuencia de cada letra en la oración
    for caracter in oracion:
        if caracter.isalpha():
            frecuencia[caracter] = frecuencia.get(caracter, 0) + 1
    return frecuencia

def descifrar_oracion(oracion_cifrada, palabras_espanol):
    # Inicializar la oración descifrada
    oracion_descifrada = ""
    # Iterar sobre cada posible corrimiento
    for corrimiento in range(1, 26):
        oracion_descifrada = cifrado_cesar(oracion_cifrada, -corrimiento)  # Corrimiento hacia el lado opuesto
        palabras = oracion_descifrada.split()
        # Verificar si alguna palabra en español está en la oración descifrada
        for palabra in palabras:
            if palabra.lower() in palabras_espanol:
                return oracion_descifrada, corrimiento
    # Si no se encuentra ninguna palabra en español en ninguna de las descifras, retornar None
    return None, None

def cifrado_cesar(oracion, corrimiento):
    # Inicializar la oración cifrada
    oracion_cifrada = ""
    # Iterar sobre cada caracter en la oración
    for caracter in oracion:
        # Verificar si el caracter es una letra
        if caracter.isalpha():
            # Obtener el código ASCII del caracter
            codigo_ascii = ord(caracter)
            # Aplicar el corrimiento sumando el valor del corrimiento
            codigo_ascii_cifrado = codigo_ascii + corrimiento
            # Verificar si el caracter es mayúscula o minúscula
            if caracter.islower():
                # Ajustar el corrimiento si el caracter cifrado está fuera del rango de letras minúsculas
                if codigo_ascii_cifrado > ord('z'):
                    codigo_ascii_cifrado -= 26
                elif codigo_ascii_cifrado < ord('a'):
                    codigo_ascii_cifrado += 26
            elif caracter.isupper():
                # Ajustar el corrimiento si el caracter cifrado está fuera del rango de letras mayúsculas
                if codigo_ascii_cifrado > ord('Z'):
                    codigo_ascii_cifrado -= 26
                elif codigo_ascii_cifrado < ord('A'):
                    codigo_ascii_cifrado += 26
            # Convertir el código ASCII cifrado de vuelta a caracter y agregarlo a la oración cifrada
            caracter_cifrado = chr(codigo_ascii_cifrado)
            oracion_cifrada += caracter_cifrado
        else:
            # Si el caracter no es una letra, agregarlo a la oración cifrada sin modificar
            oracion_cifrada += caracter
    return oracion_cifrada

def main():
    if len(sys.argv) != 2:
        print("Uso: python3 readv2.py <archivo.pcapng>")
        sys.exit(1)

    pcap_file = sys.argv[1]
    payloads_icmp = obtener_payloads_icmp(pcap_file)
    # Concatenar todos los símbolos en una sola cadena
    oracion = ''.join(payloads_icmp)
    print("Oración formada por los símbolos en los paquetes ICMP:", oracion)
    
    # Descifrar la oración y encontrar la correcta
    oracion_descifrada, corrimiento_correcto = descifrar_oracion(oracion, palabras_espanol)

    # Aplicar corrimiento para cada posible valor de corrimiento y mostrar las oraciones cifradas
    for corrimiento in range(1, 26):
        oracion_cifrada = cifrado_cesar(oracion, -corrimiento)  # Corrimiento hacia el lado opuesto
        if corrimiento == corrimiento_correcto:
            print(f"Oración cifrada con corrimiento {corrimiento}: \033[92m{oracion_cifrada}\033[0m")
        else:
            print(f"Oración cifrada con corrimiento {corrimiento}: {oracion_cifrada}")

if __name__ == "__main__":
    main()
