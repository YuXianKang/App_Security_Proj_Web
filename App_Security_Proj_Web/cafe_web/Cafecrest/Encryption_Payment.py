from cryptography.fernet import Fernet
import os
import base64

# Define the path to the encoded key file
encoded_key_file_path = './encryption_key.key'

# Check if the encoded key file exists
if not os.path.exists(encoded_key_file_path):
    # Generate the key once
    key = Fernet.generate_key()

    # Encode the key using Base64
    encoded_key_base64 = base64.urlsafe_b64encode(key)

    # Convert the base64-encoded key to a hexadecimal string
    encoded_key_hex = encoded_key_base64.decode('utf-8').replace('-', '').replace('_', '')

    # Write the hexadecimal-encoded key to the file
    with open(encoded_key_file_path, 'wb') as encoded_key_file:
        encoded_key_file.write(encoded_key_hex.encode('utf-8'))
else:
    # Load the hexadecimal-encoded key from the file
    with open(encoded_key_file_path, 'rb') as encoded_key_file:
        encoded_key_hex = encoded_key_file.read().decode('utf-8')

    # Convert the hexadecimal-encoded key back to bytes
    key = base64.urlsafe_b64decode(encoded_key_hex.replace('=', '-').replace('+', '/'))

    cipher_suite = Fernet(key)

    def encrypt_data(data):
        cipher_text = cipher_suite.encrypt(data.encode())
        return cipher_text

    def decrypt_data(data):
        plain_text = cipher_suite.decrypt(data).decode()
        return plain_text
