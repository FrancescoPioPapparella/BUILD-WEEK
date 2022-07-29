import socket

target = input('Insericsi  l''IP da scanzionare: ')
portrange = input('Inserisci l''intervallo di porta da scanzionare: ')

lowport = int(portrange.split('-')[0])
highport = int(portrange.split('-')[1])

print('Scan di host ', target, ' dalla porta ', lowport, ' alla porta ', highport)

for port in range(lowport, highport+1):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	status = s.connect_ex((target, port))
	if(status == 0):
		serviceName = socket.getservbyport(port)
		print('Porta', port, '- aperta - Servizio:',serviceName)
	s.close()