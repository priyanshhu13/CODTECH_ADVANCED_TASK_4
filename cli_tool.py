import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import pyfiglet
from colorama import Fore, Style, init

# Initialize colorama for automatic color reset
init(autoreset=True)

def derive_key(password, salt, algorithm='SHA256'):
    """Generate a key from the password and salt using the specified hash algorithm."""
    supported_algorithms = {
        'MD5': hashes.MD5(),
        'SHA256': hashes.SHA256(),
        'SHA512': hashes.SHA512(),
        'SHA1': hashes.SHA1(),
    }

    if algorithm not in supported_algorithms:
        raise ValueError("Unsupported hash algorithm. Please choose 'MD5', 'SHA256', 'SHA512', or 'SHA1'.")

    kdf = PBKDF2HMAC(
        algorithm=supported_algorithms[algorithm],
        length=32,  # AES-256 requires a 32-byte key
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )
    return kdf.derive(password.encode())

def encrypt_data(filepath, password, algorithm):
    """Encrypt a file using the specified hash algorithm."""
    salt = os.urandom(16)
    iv = os.urandom(16)
    key = derive_key(password, salt, algorithm)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(filepath, 'rb') as file:
        plaintext = file.read()

    padding_length = 16 - len(plaintext) % 16
    plaintext += bytes([padding_length]) * padding_length

    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    with open(filepath + '.enc', 'wb') as encrypted_file:
        encrypted_file.write(salt + iv + ciphertext)
    
    print(Fore.GREEN + f"File encrypted: {filepath}.enc")

def decrypt_data(filepath, password, algorithm):
    """Decrypt an encrypted file using the specified hash algorithm."""
    try:
        with open(filepath, 'rb') as encrypted_file:
            content = encrypted_file.read()

        salt, iv, ciphertext = content[:16], content[16:32], content[32:]
        key = derive_key(password, salt, algorithm)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        padding_length = plaintext[-1]
        if padding_length < 1 or padding_length > 16:
            raise ValueError("Invalid padding")
        plaintext = plaintext[:-padding_length]

        original_path = filepath.replace('.enc', '')
        with open(original_path, 'wb') as original_file:
            original_file.write(plaintext)
        
        print(Fore.GREEN + f"File decrypted: {original_path}")
    
    except Exception as e:
        print(Fore.RED + f"Error during decryption: {str(e)}")

def main():
    """Main function to run the encryption & decryption tool."""
    logo_text = pyfiglet.figlet_format("Advanced Encryption Tool PS")
    print(Fore.CYAN + logo_text)
    print(Fore.GREEN + "Created by : Premkumar Soni")
    print(Fore.YELLOW + "Advanced Encryption Tool")
    print(Fore.MAGENTA + "Choose: [1] Encrypt File  [2] Decrypt File")
    choice = input(Fore.CYAN + "Enter your choice (1/2): ")

    filepath = input(Fore.CYAN + "Enter the file path: ")
    password = input(Fore.CYAN + "Enter password for encryption/decryption: ")
    algorithm = input(Fore.CYAN + "Select hash algorithm (MD5, SHA256, SHA512, SHA1): ").upper()

    if choice == '1':
        encrypt_data(filepath, password, algorithm)
    elif choice == '2':
        decrypt_data(filepath, password, algorithm)
    else:
        print(Fore.RED + "Invalid choice. Please choose either 1 or 2.")

if __name__ == "__main__":
    main()
