import socket
import json
import des
import rsa

# Create a socket object
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to the server
host = socket.gethostname()
port = 5050
client_socket.connect((host, port))

# Receive public key from server
serialized_public_key = client_socket.recv(1024)
public_key = json.loads(serialized_public_key.decode('utf-8'))
print(f"Received public key: {public_key}\n")

# Initialize DES key
key = "0000000000000ABC"

# Encrypt DES key using RSA
encrypted_key = rsa.encrypt(key, public_key)
encrypted_key = str(encrypted_key)
print(f"Encrypted DES key: {encrypted_key}\n")

# Send encrypted DES key to server
client_socket.sendall(encrypted_key.encode())

# Generate the round key
round_key = des.generate_round_key(key)

while True:
    while True:
        message_to_send = input("Enter a message to send to the server: ")
        if message_to_send == "exit":
            client_socket.close()
            exit()
        try:
            if not message_to_send:
                raise ValueError("please enter a non-empty message\n")
            if len(message_to_send) != 16:
                raise ValueError("please enter a 64-bit hex string\n")
            if not all(char in "0123456789ABCDEF" for char in message_to_send):
                raise ValueError("please enter a 64-bit hex string\n")
            break
        except ValueError as e:
            print("Error:", e)
            continue

    message_to_send = des.encrypt(message_to_send, round_key)
    print(f"Encrypted message: {message_to_send}\n")

    client_socket.sendall(message_to_send.encode())

    data = client_socket.recv(1024)
    if not data:
        break
    data = data.decode('utf-8')
    print(f"Received from server: {data}")

    data = des.decrypt(data, round_key)
    print(f"Decrypted message: {data}\n")
