import socket

target_host = "192.168.1.27"
target_port = 5556

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

client.connect((target_host, target_port))

while True:
    message = byte(input(" #> "))
    client.send(message)
    response = client.recv(4096)

print(response.decode())
client.close()