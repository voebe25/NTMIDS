from bluetooth import *

socket = BluetoothSocket(RFCOMM)
socket.connect(("78:9E:D0:B6:D1:52",4))
socket.send("file.txt")
socket.close()
