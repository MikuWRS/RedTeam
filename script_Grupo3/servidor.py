import socket, struct, sys

# Esta funcion asegura que se reciban los bytes que indican el tamano del archivo que sera enviado,
# que es codificado por el cliente via struct.pack(), 
# esta funcion genera una secuencia de bytes que representan el tamano del archivo.

def recibir_tamano_archivo(sck: socket.socket):
	fmt =  "<Q"
	bytes_esperados = struct.calcsize(fmt)
	bytes_recibidos = 0
	stream = bytes()
	while bytes_recibidos < bytes_esperados:
		chunk = sck.recv(bytes_esperados - bytes_recibidos)  # ojo, esto es la diferencia de tamano
		stream += chunk
		bytes_recibidos += len(chunk)
	filesize = struct.unpack(fmt, stream)[0]
	return filesize


def recibir_archivo(sck: socket.socket, filename):
	filesize = recibir_tamano_archivo(sck) # lee del socket el tamano del archivo en bytes
	with open(filename, "wb") as f: # se abre el archivo, abrirlo de esta forma lo cierra automaticamente.
		bytes_recibidos = 0

		# Recoge los datos en bloques de 1024 bytes hasta que se llega al tamano total del archivo
		while bytes_recibidos < filesize:
			chunk = sck.recv(1024)
			if chunk:
				f.write(chunk)
				bytes_recibidos += len(chunk) # aumentamos la cantidad de bytes recibidos

def conectarse(filename):
	#                              Ip      Port
	with socket.create_server(("localhost",6190)) as server:
		print("[*] Esperando Cliente...\n")
		conn, address = server.accept()
		print(f"{address[0]}:{address[1]} conectado.\n")
		print("[*] Recibiendo Archivos...\n")
		recibir_archivo(conn, filename) # Esta linea llama a la funcion de arriba, hay que darle nombre al segundo parametro dependiendo del tipo de archivo que enviaremos
		print("[+] Archivo Recibido...\n")
	print("[!] Conexion finalizada\n")

def usage(nombre):
	print("Usage: python3 ",nombre, " [Opciones]\n")
	print("\tOpciones:\n")
	print("\t -H nombre_archivo_hosts\n")
	print("\t -P nombre_archivo_ports\n")
	print("\t -S nombre_archivo_sniffer (Extension .pcap)\n")
	print("\t Nota: Se pueden usar todas las opciones juntas\n")
# nombre.py -H nombre1 -P nombre2 -S nombre3
#     1      2     3    4    5     6    7

def main():
	argumentos = len(sys.argv)-1
	if(argumentos > 6 or argumentos < 2):
		usage(sys.argv[0])
		sys.exit(1)
	elif('-H' not in sys.argv[1:] and '-P' not in sys.argv[1:] and '-S' not in sys.argv[1:]):
		usage(sys.argv[0])
		sys.exit(1)
	else:
		if('-H' in sys.argv[1:]):
			name_host = sys.argv[sys.argv.index('-H') + 1]
			conectarse(name_host)
		if('-P' in sys.argv[1:]):
			name_port = sys.argv[sys.argv.index('-P') + 1]
			conectarse(name_port)
		if('-S' in sys.argv[1:]):
			name_snif = sys.argv[sys.argv.index('-S') + 1]
			conectarse(name_snif)

if __name__ == '__main__':
	main()
