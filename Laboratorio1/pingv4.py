import sys
import time
import struct
import scapy.all as scapy

# identification es el número del proceso del sistema
id_ipv4 = id_icmp = scapy.RandShort()

#  Obtiene el valor del identifier desde un archivo
try:
    with open("identifier.txt", "r") as file:
        id_icmp = int(file.read())
except FileNotFoundError:
    id_icmp = 1

# Incrementa el identifier para el siguiente uso
with open("identifier.txt", "w") as file:
    file.write(str(id_icmp + 1))

# Timestamp en los primeros 8 bytes del payload
timestamp = struct.pack("<Q", int(time.time()))

# Los siguientes 8 bytes son como un paquete ICMP
data_icmp = scapy.ICMP(id=0, seq=0).build()

# Bytes desde 0x10 hasta 0x37
icmp_ping = bytes(range(0x10, 0x38))

#  llega el mensaje cifrado
if len(sys.argv) != 2:
    print("Uso: python3 icmp_cesar.py <mensaje>")
    sys.exit(1)

ip_destino = "8.8.8.8"
mensaje_cifrado = sys.argv[1]

# Sequence number incremental (>=1) en el campo ICMP
# Creacion del campo Payload
packets = []
for i, caracter in enumerate(mensaje_cifrado):
    payload = timestamp + caracter.encode() + data_icmp + icmp_ping 
    payload = payload[:-1]  # Eliminar un byte antes de codificar el caracter
    packet = scapy.IP(dst=ip_destino, id=id_ipv4, flags="DF") / scapy.ICMP(id=id_icmp, seq=i + 1) / payload
    packets.append(packet)

# Envía los paquetes
for pack in packets: 
    # Esperar un segundo antes de enviar el siguiente paquete
    time.sleep(1)
    scapy.send(pack)  
    print("Sent 1 packets")
