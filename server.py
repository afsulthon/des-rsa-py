import socket
import json
import des
import rsa

# Create a socket object
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the socket to a specific address and port
host = socket.gethostname()
port = 5050
server_socket.bind((host, port))

# Listen for incoming connections
server_socket.listen(1)
print(f"Server listening on {host}:{port}...")

# Wait for a connection from a client
print("Waiting for connection...")
client_socket, addr = server_socket.accept()
print(f"Got connection from: {addr}\n")

# RSA configuration
p = 97
q = 89
n = p * q
phi_n = (p - 1) * (q - 1)

# Generate public keys
e = rsa.generate_e(phi_n)
public_key = {"e": e, "n": n}
print(f"Public key: {public_key}")

# Generate private keys
d = pow(e, -1, phi_n)
private_key = {"d": d, "n": n}
print(f"Private key: {private_key}\n")

# Send public key to client
serialized_public_key = json.dumps(public_key).encode('utf-8')
client_socket.sendall(serialized_public_key)

# Receive encrypted DES key from client
encrypted_key = client_socket.recv(1024)
encrypted_key = int(encrypted_key.decode('utf-8'))
print(f"Received encrypted DES key: {encrypted_key}")

# Decrypt DES key
key = rsa.decrypt(encrypted_key, private_key)
print(f"Decrypted DES key: {key}\n")

# Generate the round key
round_key = des.generate_round_key(key)

while True:
    # Receive data from the client
    data = client_socket.recv(1024)
    if not data:
        break
    data = data.decode('utf-8')
    print(f"Received from client: {data}")

    # Decrypt the message using DES
    data = des.decrypt(data, round_key)
    print(f"Decrypted message: {data}\n")

    # Get input from the user and validate it
    while True:
        message_to_send = input("Enter a message to send to the client: ")
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

    # Encrypt the message using DES
    message_to_send = des.encrypt(message_to_send, round_key)
    print(f"Encrypted message: {message_to_send}\n")

    # Send the message to the client
    client_socket.sendall(message_to_send.encode())
