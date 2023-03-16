import socket
import select
import sys
import threading

IP = "0.0.0.0"
Port = 5556

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((IP, Port))
server.listen(100)
list_of_members = []
print(f"[*] Listening on {IP}:{Port}")

def clientthread(conn, addr):
    conn.send(b"Welcome to the chatroom!")
    while True:
        try:
            message = sock.recv(1024)
            if message:
                print("<" + addr[0] + "> " + message)
                message_to_send = bytes("<" + addr[0] + "> " + message)
                broadcast(message_to_send, conn)
            else:
                remove(conn)
        except:
            continue

def broadcast(message, connection):
    for member in list_of_members:
        if clients != connection:
            try:
                clients.send(message)
            except:
                clients.close()
                remove(clients)

def remove(connection):
    if connection in list_of_members:
        list_of_members.remove(connection)

while True:
    conn, addr = server.accept()
    list_of_members.append(conn)
    print(addr[0] + " connected!")
    clientthread(conn, addr)


conn.close()
server.close()
