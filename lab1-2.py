#Librerias necesarias.
from datetime import datetime
import socket, struct, os, random, sys, secrets

def enviar_icmp_request(data, destino, sequencia):
#Crea un socket de red para enviar y recibir paquetes ICMP, usando las familias de IPv4, especificando el protocolo, etc.
    icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
#Obtener el id del proceso actual en un rango de 16 bits.
    id_paquete = os.getpid() & 0xFFFF  
#Crea un valor de timestamp actual y lo convierte en una secuencia de bytes que se puede utilizar.
    timestamp = struct.pack('d', datetime.now().timestamp())
#Genera la secuencia de dos bytes aleatorios, le damos un n=2 bytes ya que asi se define por protocolo.
    bytes_aleatorios = secrets.token_bytes(2)
#Variables para mantener payload ICMP (desde 0x10 a 0x37) y payload ICMP (5 bytes 0x00) requeridos por rubrica.
#La variabel payload crea una secuencia de cinco bytes, cada uno establecido en 0x00, mientras que rango_payload entrega una secuencia de bytes que contiene todos los enteros en el rango de 0x10 a 0x37.
    payload = b'\x00\x00\x00\x00\x00'
    rango_payload = bytes([i for i in range(0x10, 0x38)])  
#Se concatenan todas las variables generadas anteriormente para generar el campo data del paquete ICMP.   
    paquete_icmp_data = timestamp + bytes([data]) + bytes_aleatorios + payload + rango_payload
#Con esto se construye un paquete ICMP completo concatenando el encabezado ICMP empaquetado y los datos del paquete ICMP en una sola secuencia de bytes.
    paquete_icmp_bytes = struct.pack("!BBHHH", 8, 0, 0, id_paquete, sequencia) + paquete_icmp_data      
#Calculo del checksum agregando los valores de cada par de bytes del paquete ICMP. 
#Si la longitud del paquete es impar, el último byte se considera como si estuviera seguido por un byte cero.
    checksum = 0 #Se inicializa en 0.
#Se itera sobre los bytes del paquete ICMP de dos en dos.
    for i in range(0, len(paquete_icmp_bytes), 2):
            byte_actual = paquete_icmp_bytes[i] << 8
            byte_siguiente = paquete_icmp_bytes[i+1] if i < len(paquete_icmp_bytes) - 1 else 0    
            checksum += byte_actual + byte_siguiente

    checksum = ~(checksum + (checksum >> 16)) & 0xFFFF
#Se crea el paquete con el checksum actualizado, se envia el paquete a destino y luego de cierra el socket ICMP.
    paquete_icmp = bytearray(paquete_icmp_bytes)
    struct_checksum = struct.pack("!H", checksum)
    paquete_icmp[2:4] = struct_checksum
    icmp_socket.sendto(paquete_icmp, (destino, 0))
    icmp_socket.close()
#Medida tomada para que se verifique que se entrega un argumento valido al programa, si no es igual a 2, es decir que no pasa un script y un argumente este sale del script con un código de error.
if len(sys.argv) != 2:
    print("Usage: python3 icmp_sender.py <string>")
    exit(1)   
#Toma el string entregado y envía un paquete ICMP para cada carácter de esa cadena de string.
string = sys.argv[1]
for i in range(len(string)):    
    enviar_icmp_request(ord(string[i]), "127.0.0.1", i + 1)
    
