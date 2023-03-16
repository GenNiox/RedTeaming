import socket

target_host = "192.168.1.27"
target_port = 5556

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

client.connect((target_host, target_port))

client.send(b"TEST-1-2-3-4!")

response = client.recv(4096)

print(response.decode())
client.close()