import socket
import threading
from datetime import datetime
import logging
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from hashlib import sha256

# Configure logging to write logs to a file
logging.basicConfig(
    filename="server_log.txt",  # Name of the log file
    level=logging.INFO,        # Log level
    format="%(asctime)s - %(message)s",  # Log format
    datefmt="%Y-%m-%d %H:%M:%S"  # Date format
)

# Diffie-Hellman parameters
PRIME = 23  # A small prime number for demonstration (use a large prime in production)
BASE = 5    # A base number for the calculation (common choice is 2 or 5)

def generate_shared_key(private_key, client_public_key):
    """
    Generate the shared secret key using the private key and the client's public key.
    """
    shared_key = pow(client_public_key, private_key, PRIME)  # (client_public_key ** private_key) % PRIME
    # Hash the shared key to derive the encryption key
    return sha256(str(shared_key).encode()).digest()

# Function to get the current server time
def get_current_time():
    """
    Get the current time formatted as HH:mm:ss.SSS
    """
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]  # Remove the last 3 microsecond digits

# Function to handle each client connection
def handle_client(client_socket, client_address):
    """
    Handle a single client connection.

    :param client_socket: The socket representing the client connection.
    :param client_address: The client's address.
    """
    print(f"Client connected: {client_address}")
    try:
        # Generate Diffie-Hellman keys
        server_private_key = get_random_bytes(16)  # Generate private key
        server_private_key = int.from_bytes(server_private_key, 'big') % PRIME
        server_public_key = pow(BASE, server_private_key, PRIME)  # (BASE ** private_key) % PRIME

        # Exchange public keys with the client
        client_socket.sendall(str(server_public_key).encode('utf-8'))  # Send server public key
        client_public_key = int(client_socket.recv(1024).decode('utf-8'))  # Receive client's public key

        # Generate the shared secret key
        encryption_key = generate_shared_key(server_private_key, client_public_key)
        print(f"Shared encryption key established: {encryption_key.hex()}")

        # Receive and decrypt the client's time
        encrypted_message = client_socket.recv(1024)
        cipher = AES.new(encryption_key, AES.MODE_CBC, iv=encryption_key[:16])
        client_time = unpad(cipher.decrypt(encrypted_message), AES.block_size).decode('utf-8')
        print(f"Decrypted client time ({client_address}): {client_time}")

        # Get the current server time
        server_time = get_current_time()

        # Encrypt and send the server time
        cipher = AES.new(encryption_key, AES.MODE_CBC, iv=encryption_key[:16])
        encrypted_time = cipher.encrypt(pad(server_time.encode('utf-8'), AES.block_size))
        client_socket.sendall(encrypted_time)

        # Log the synchronization request
        log_message = f"({client_address[0]}) Time Sync Request: Local Time ({client_time}) --> Sent Time ({server_time})"
        logging.info(log_message)
    except Exception as e:
        print(f"Error handling client ({client_address}): {e}")
    finally:
        # Close the client socket
        client_socket.close()
        print(f"Connection closed: {client_address}")

# Main server loop
def start_server(host='127.0.0.1', port=8082):
    """
    Start the TCP server to handle time synchronization.

    :param host: The host IP address to bind the server to.
    :param port: The port to listen on.
    """
    print(f"Starting server on {host}:{port}...")
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)  # Allow up to 5 pending connections
    print(f"Server is listening on {host}:{port}")

    try:
        while True:
            # Accept a new client connection
            client_socket, client_address = server_socket.accept()

            # Handle the client in a new thread
            client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
            client_thread.daemon = True  # Ensure threads close with the main program
            client_thread.start()
    except KeyboardInterrupt:
        print("\nServer shutting down...")
    finally:
        server_socket.close()

if __name__ == "__main__":
    start_server()
