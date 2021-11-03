
#=========================================#
#                                         #
#      Grupo 3 Diplomado RedTeam 2021     #
#                                         #
# - Sebastian Doll                        #
# - Sebastian Holloway                    #
# - Cristian Munoz                        # 
# - Cristian Vargas                       #
# - Cristian Vera                         #
#                                         #
#                                         #
#=========================================#


import sys, socket, struct, time, signal, threading, os, tempfile
from queue import Queue

#verbose = False
enviar = False

servidor = "localhost" # Cambiar servidor
puerto_servidor = 6190 # Cambiar puerto del servidor, debe ser el mismo en el servidor.py

def usage(nombre):
	print("Usage: python3 ",nombre," [opciones]\n")
	print("\t Opciones disponibles\n")
	print("\t\t -h = help\n")
	print("\t\t -host = escaner de host (toma alrededor de 4 minutos)\n")
	print("\t\t -port = escaner de puertos (toma mas de 1 hora)\n")
	print("\t\t -snif = sniffer\n")
	print("\t\t -all = ejecuta todos los escaners y el sniffer al final\n")
	#print("\t\t -v = ejecuta en modo verboso, por defecto guardara en un archivo si no se ocupa\n")
	print("\t\t -enviar = Envia la data a un servidor local, por defecto es la localhost.\n")

def error():
	print("[!] Error...")
	sys.exit(1)

def def_handler(sig, frame):
	print("\n[!] Saliendo...\n")
	sys.exit(1)

def enviar_archivos(sck: socket.socket, filename):

	filesize = os.path.getsize(filename) # Obtiene el tamano del archivo
	sck.sendall(struct.pack("<Q", filesize)) # Informa al servidor el tamano del archivo

	with open(filename, "rb") as f:
		while bytes_leidos := f.read(1024):
			sck.sendall(bytes_leidos)
	

# Referencia: https://www.bitforestinfo.com/blog/01/13/save-python-raw-tcpip-packet-into-pcap-files.html
def sniffer():
	
	#enviardata = input("\t Quieres enviar la data a un servidor? (y/n)\n\t (n) guardara en un archivo pcap.\n")
	if(enviar == True):
		ed = 1
	elif(enviar == False):
		ed = 0


	# Global Header para archivos PCAP que sean leidos por WireShark
	PCAP_GLOBAL_HEADER_FMT = '@ I H H i I I I '
	PCAP_MAGICAL_NUMBER = 2712847316
	PCAP_MJ_VERN_NUMBER = 2
	PCAP_MI_VERN_NUMBER = 4
	PCAP_LOCAL_CORECTIN = 0
	PCAP_ACCUR_TIMSTAMP = 0
	PCAP_MAX_LENGTH_CAP = 65535
	PCAP_DATA_LINK_TYPE = 1

	# Inicializacion del socket, si falla, se sale.

	try:
		sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
	except socket.error:
		print('[!] Error: El socket no se pudo crear... \n')
		sys.exit(1)
	
	if(verbose == False):
		if(enviar == True):
			# Apertura de archivo y guardado del cabecero
			file = open("output.pcap","wb")
			file.write(struct.pack('@ I H H i I I I ', PCAP_MAGICAL_NUMBER, PCAP_MJ_VERN_NUMBER, PCAP_MI_VERN_NUMBER, PCAP_LOCAL_CORECTIN, PCAP_ACCUR_TIMSTAMP, PCAP_MAX_LENGTH_CAP, PCAP_DATA_LINK_TYPE))

			# Captura de datos
			for i in range (10000):
				raw_data, address = sock.recvfrom(65535)
				data = raw_data
				ts_sec, ts_usec = map(int, str(time.time()).split('.'))
				length = len(data)
				file.write(struct.pack('@ I I I I', ts_sec, ts_usec, length, length))
				file.write(data)
			file.close()
			with socket.create_connection((servidor, puerto_servidor)) as conexion: # Aqui hace el envio de los datos
				#print("[*] Conectando al servidor\n")
				#print("[*] Enviando Archivos\n")
				enviar_archivos(conexion, "output.pcap")
			os.remove('output.pcap')
		else:
			# Apertura de archivo y guardado del cabecero
			file = open("output.pcap","wb")
			file.write(struct.pack('@ I H H i I I I ', PCAP_MAGICAL_NUMBER, PCAP_MJ_VERN_NUMBER, PCAP_MI_VERN_NUMBER, PCAP_LOCAL_CORECTIN, PCAP_ACCUR_TIMSTAMP, PCAP_MAX_LENGTH_CAP, PCAP_DATA_LINK_TYPE))

			# Captura de datos
			for i in range (10000):
				raw_data, address = sock.recvfrom(65535)
				data = raw_data
				ts_sec, ts_usec = map(int, str(time.time()).split('.'))
				length = len(data)
				file.write(struct.pack('@ I I I I', ts_sec, ts_usec, length, length))
				file.write(data)
			file.close()
	else:
		def get_mac_address(bytesString):
			bytesString2 = map('{:02x}'.format, bytesString) # Convierte direcciones mac crudo a formato hexa
			destination_mac = ':'.join(bytesString2).upper()
			return destination_mac

		for i in range(10000):
			raw_data, address = sock.recvfrom(65535)
			destination_mac, src_mac, ethernet_proto = struct.unpack('! 6s 6s H', raw_data[:14])
			
			destination_mac = get_mac_address(destination_mac)
			src_mac = get_mac_address(src_mac)
			ethernet_proto = socket.htons(ethernet_proto)
			data = raw_data[14:]

			print('\nFrame {} de Ethernet:'.format(i))
			print('\tDestino: {}, Fuente: {}, Protocolo: {}'.format(destination_mac, src_mac, ethernet_proto))
			
			if (ethernet_proto == 8):
				version_header_len = data[0]
				version = version_header_len >> 4
				header_len = (version_header_len & 15) * 4
				ttl,proto,src,target = struct.unpack('! 8x B B 2x 4s 4s', data[:20]) # Desempaquetado

			src = '.'.join(map(str,src))
			target = '.'.join(map(str,target))

			print('Paquete IPv4:')
			print('\tVersion: {}, Largo de Cabecera: {}, TTL: {}'.format(version,header_len,ttl))
			print('\tProtocolo: {}, Fuente: {}, Target: {}'.format(proto,src,target))
		
def port_scanner():
	# Este toma demasiado tiempo en ejecutarse, para probar su funcionamiento, se recomienda cambiar el rango de puertos hasta el puerto 81
	target = input('Target IP: ')
	if(verbose == False or enviar == True):
		file=open("PortDiscovery.txt","a")

	# el for debe ir desde el 0 al 65536 para que el range tome los 65535 puertos totales
	for port in range(1,65536): # Rango de puertos, cambiar para pruebas
		s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		result=s.connect_ex((target,port))
		if(result == 0):
			if(verbose == True):
				print("Puerto abierto {}\n".format(port))
				if(enviar == True):
					file.write("Puerto abierto {}\n".format(port))
			else:
				file.write("Puerto abierto {}\n".format(port))
	s.close()
	if(verbose == False):
		file.close()
	if(enviar == True):
		with socket.create_connection((servidor, puerto_servidor)) as conexion:
			#print("[*] Conectando al servidor\n")
			#print("[*] Enviando Archivos\n")
			enviar_archivos(conexion, "PortDiscovery.txt")
		os.remove('PortDiscovery.txt')
			

def host_scanner():
	
	if(verbose == False or enviar == True):
		file = open("hosts_descubiertos.txt","a")

	target_ip = input("\tIngrese la Ip Objetivo: \n") # Pedimos la Ip
	ip_dividida = target_ip.split('.') # Dividimos la Ip por octetos [X1.X2.X3.X4] => [X1,X2,X3,X4]
	
	for i in range(1,255):
		ip = (ip_dividida[0],ip_dividida[1],ip_dividida[2],str(i)) # Rearmamos la ip modificando el ultimo octeto, se guarda como array
		ipping = ".".join(ip) # Aqui convertimos ese array a un string

		ping = os.system("timeout 1 bash -c 'ping -c 1 '" + ipping + "' > /dev/null 2>&1'") # Realizamos la consulta para una consola de linux
		
		if(ping == 0): # si ese resultado es 0 quiere decir que fue exitoso
			if(verbose == True):
				print(ipping,"existe")
				if(enviar == True):
					file.write("{}\n".format(ipping))
			else:
				file.write("{}\n".format(ipping))

	if(verbose == False):
		file.close()
	if(enviar == True):
		with socket.create_connection((servidor, puerto_servidor)) as conexion:
			#print("[*] Conectando al servidor\n")
			#print("[*] Enviando Archivos\n")
			enviar_archivos(conexion, "hosts_descubiertos.txt")
		os.remove('hosts_descubiertos.txt')


# Ctrl + C
signal.signal(signal.SIGINT, def_handler)

# nombre.py -port -enviar -v
#     1       2      3     4  
def main():
	global verbose, enviar
	argumentos = len(sys.argv)-1
	if(argumentos > 3 or argumentos < 2):
		usage(sys.argv[0])
		sys.exit(1)
	elif('-host' not in sys.argv[1:] and '-port' not in sys.argv[1:] and '-snif' not in sys.argv[1:] and '-enviar' not in sys.argv[1:]):
		usage(sys.argv[0])
		sys.exit(1)
	else:
		if('-host' in sys.argv[1:]):
			#if('-v' in sys.argv[1:]):
			#	verbose = True
			if('-enviar' in sys.argv[1:]):
				enviar = True
			#print("Parametro: -host habilidato\nModo verbose:",verbose,"\nModo Enviar: ",enviar,"\n")
			host_scanner()
		if('-port' in sys.argv[1:]):
			#if('-v' in sys.argv[1:]):
			#	verbose = True
			if('-enviar' in sys.argv[1:]):
				enviar = True
			#print("Parametro: -port habilidato\nModo verbose:",verbose,"\nModo Enviar: ",enviar,"\n")
			port_scanner()
		if('-snif' in sys.argv[1:]):
			#if('-v' in sys.argv[1:] and '-enviar' in sys.argv[1:]):
			#	print("El sniffer no puede enviar y ver a la vez los datos, es una o la otra\n")
			#	sys.exit(1)
			#if('-v' in sys.argv[1:]):
			#	verbose = True
			if('-enviar' in sys.argv[1:]):
				enviar = True
			#print("Parametro: -snif habilidato\nModo verbose:",verbose,"\nModo Enviar: ",enviar,"\n")
			sniffer()
		if('-all' in sys.argv[1:]):
			#if('-v' in sys.argv[1:]):
			#	verbose = True
			if('-enviar' in sys.argv[1:]):
				enviar = True
			#print("Parametro: -all habilidato\nModo verbose:",verbose,"\nModo Enviar: ",enviar,"\n")
			host_scanner()
			port_scanner()
			#if('-v' in sys.argv[1:] and '-enviar' in sys.argv[1:]):
			#	print("El sniffer no puede enviar y ver a la vez los datos, es una o la otra, se deshabilitara el modo verbose\n")
			#	verbose = False
			sniffer()


if __name__ == '__main__':
	main()
	


