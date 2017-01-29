import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("192.168.59.254",10000))
print "connection made"
sock.sendall("Getinfo")
r = sock.recv(4096)
print "sent"
print r
sock.close()
