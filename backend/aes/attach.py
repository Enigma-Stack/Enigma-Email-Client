from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import secrets

def generate_random_key():
    # Generate 32 random bytes
    random_key = secrets.token_bytes(32)
    return random_key

def pad(data):
    block_size = 16
    padding = block_size - len(data) % block_size
    return data + bytes([padding] * padding)

def unpad(data):
    padding = data[-1]
    return data[:-padding]

def encrypt_file(input_file, output_file, key):
    with open(input_file, 'rb') as file:
        plaintext = file.read()

    plaintext = pad(plaintext)

    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    # print("Encrypted Attachment File: ")
    # print(ciphertext)

    with open(output_file, 'wb') as file:
        file.write(ciphertext)

def decrypt_file(input_file, output_file, key):
    with open(input_file, 'rb') as file:
        ciphertext = file.read()

    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    decrypted_data = unpad(decrypted_data)
    # print("Decrypted Attachment File: ")
    # print(decrypted_data)

    with open(output_file, 'wb') as file:
        file.write(decrypted_data)


# Example usage
key = generate_random_key()
print("Generated Key:", key)

# Encrypt a file
encrypt_file('test.JPG', 'encrypted_file.enc', key)

# Decrypt the file
decrypt_file('encrypted_file.enc', 'decrypted_file.jpg', key)