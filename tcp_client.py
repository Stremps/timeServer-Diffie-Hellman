import socket
from datetime import datetime, timedelta
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from hashlib import sha256
import random

# Diffie-Hellman parameters
PRIME = 23  # A small prime number for demonstration (use a large prime in production)
BASE = 5    # A base number for the calculation (common choice is 2 or 5)

def generate_shared_key(private_key, server_public_key):
    """
    Generate the shared secret key using the private key and the server's public key.
    """
    shared_key = pow(server_public_key, private_key, PRIME)  # (server_public_key ** private_key) % PRIME
    # Hash the shared key to derive the encryption key
    return sha256(str(shared_key).encode()).digest()

def simulate_desynchronized_clock():
    """
    Simulates a random desynchronized clock time in HH:mm:ss format.
    """
    random_hour = random.randint(0, 23)
    random_minute = random.randint(0, 59)
    random_second = random.randint(0, 59)
    return f"{random_hour:02}:{random_minute:02}:{random_second:02}"

def parse_time_string(time_string):
    """
    Parses a time string in HH:mm:ss.SSS format to a datetime object.
    """
    return datetime.strptime(time_string, "%H:%M:%S.%f")

def tcp_client(server_address="127.0.0.1", server_port=8082):
    """
    Simulates a TCP client for time synchronization using Diffie-Hellman for encryption.

    :param server_address: The server's IP address.
    :param server_port: The server's port.
    """
    try:
        # Simulate a desynchronized clock
        local_time = simulate_desynchronized_clock()
        print(f"Local (simulated) time before sync: {local_time}")

        # Connect to the server
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((server_address, server_port))

        # Generate Diffie-Hellman keys
        client_private_key = get_random_bytes(16)  # Generate private key
        client_private_key = int.from_bytes(client_private_key, 'big') % PRIME
        client_public_key = pow(BASE, client_private_key, PRIME)  # (BASE ** private_key) % PRIME

        # Exchange public keys with the server
        server_public_key = int(client_socket.recv(1024).decode('utf-8'))  # Receive server's public key
        client_socket.sendall(str(client_public_key).encode('utf-8'))  # Send client's public key

        # Generate the shared secret key
        encryption_key = generate_shared_key(client_private_key, server_public_key)
        print(f"Shared encryption key established: {encryption_key.hex()}")

        # Encrypt and send the local time to the server
        cipher = AES.new(encryption_key, AES.MODE_CBC, iv=encryption_key[:16])
        encrypted_time = cipher.encrypt(pad(local_time.encode('utf-8'), AES.block_size))
        client_socket.sendall(encrypted_time)

        # Receive and decrypt the server's time
        encrypted_server_time = client_socket.recv(1024)
        cipher = AES.new(encryption_key, AES.MODE_CBC, iv=encryption_key[:16])
        server_time = unpad(cipher.decrypt(encrypted_server_time), AES.block_size).decode('utf-8')

        # Print the synchronized time
        print(f"Synchronized server time: {server_time}")

        # Close the connection
        client_socket.close()
    except Exception as e:
        print(f"Error in client: {e}")

if __name__ == "__main__":
    tcp_client()
