import socket

print("Starting brute force simulation...")

for i in range(30):
    s = socket.socket()

    try:
        s.connect(("127.0.0.1", 80))
    except:
        pass

    s.close()
