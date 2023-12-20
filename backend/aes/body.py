from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# def generate_hex_key():
#     # Generate a random hexadecimal key of 256 bits
#     key = os.urandom(32)  # 32 bytes for a 256-bit key
#     hex_key = key.hex()   # Convert bytes to hexadecimal
#     print(hex_key)
#     return hex_key

def aes_encrypt(plaintext, hex_key):
    print("inside aes", plaintext, type(hex_key))
    
    key = bytes.fromhex(str(hex_key))  # Convert hexadecimal key to bytes
    print("bytes", key)
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()
    print("encryptor", encryptor)
    
    # Padding the plaintext to be a multiple of 16 bytes (AES block size)
    padder = lambda s: s + (16 - len(s) % 16) * chr(16 - len(s) % 16)
    padded_plaintext = padder(str(plaintext))

    ciphertext = encryptor.update(padded_plaintext.encode()) + encryptor.finalize()
    return ciphertext.hex()

def aes_decrypt(ciphertext, hex_key):
    print("CT", ciphertext, "HK", hex_key)
    key = bytes.fromhex(hex_key)  # Convert hexadecimal key to bytes
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    decryptor = cipher.decryptor()

    decrypted_text = decryptor.update(bytes.fromhex(ciphertext)) + decryptor.finalize()
    
    # Remove padding from decrypted text
    unpadder = lambda s: s[:-ord(s[-1])]
    unpadded_text = unpadder(decrypted_text.decode())
    
    return unpadded_text

# # Example usage
# if __name__ == "__main__":
#     # Generate a random key
#     key = generate_hex_key()
#     print("Generated Key:", key)

#     # Encryption and decryption using AES
#     plaintext = "Hello, this is a secret message!"
#     print("Original Message:", plaintext)

#     encrypted_text = aes_encrypt(plaintext, key)
#     print("Encrypted Message:", encrypted_text)

#     decrypted_text = aes_decrypt(encrypted_text, key)
#     print("Decrypted Message:", decrypted_text)