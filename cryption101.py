import argparse
import os
import re
from cryptography.fernet import Fernet

# Caesar Cipher functions
def caesar_cipher(text, shift):
    def shift_char(char):
        if char.isalpha():
            offset = 65 if char.isupper() else 97
            return chr((ord(char) - offset + shift) % 26 + offset)
        return char

    return ''.join(shift_char(char) for char in text)

# Password strength checker functions
def check_password_strength(password):
    length = len(password)
    if re.findall(r'[A-Za-z0-9~!@#$%^&*()]', password):
        if (re.findall(r'[~!@#$%^&*()_+]', password) or re.findall(r'[A-Z]', password)) and length >= 8:
            if not re.findall(r'[~!@#$%^&*()_+]', password):
                print("Password should use special characters.")
            if not re.findall(r'[A-Z]', password):
                print("Password should use capital letters.")
            
            if re.findall(r'[~!@#$%^&*()_+]', password) and re.findall(r'[A-Z]', password):
                print("Strong password.")
        else:
            print("Not strong. Use special characters and capital letters.")
    else:
        print("Type a valid password.")

# XOR encrypt/decrypt functions
def xor_encrypt_decrypt(input_path, output_path, key):
    try:
        with open(input_path, "rb") as fp:
            image = bytearray(fp.read())
        
        for index, value in enumerate(image):
            image[index] = value ^ key
        
        with open(output_path, "wb") as fp:
            fp.write(image)
        
        print(f"Image processing completed successfully. Output saved to {output_path}")
    except FileNotFoundError:
        print(f"Error: File not found - {input_path}")
    except Exception as e:
        print(f"An error occurred: {e}")

# File encryption functions
def encrypt_files():
    files = [file for file in os.listdir() if os.path.isfile(file) and file not in ["encrypt.py", "decrypt.py", "TheKey.key"]]
    key = Fernet.generate_key()

    with open('TheKey.key', "wb") as thekey:
        thekey.write(key)

    for file in files:
        with open(file, 'rb') as theFile:
            contents = theFile.read()
        contents_encryption = Fernet(key).encrypt(contents)
        with open(file, 'wb') as theFile:
            theFile.write(contents_encryption)
    print("Files encrypted successfully.")

# File decryption functions
def decrypt_files(user_key):
    files = [file for file in os.listdir() if os.path.isfile(file) and file not in ["encrypt.py", "decrypt.py", "TheKey.key"]]

    try:
        with open('TheKey.key', 'rb') as key_file:
            secret_key = key_file.read()

        if user_key == "randsome":
            for file in files:
                with open(file, 'rb') as theFile:
                    contents = theFile.read()
                contents_decryption = Fernet(secret_key).decrypt(contents)
                with open(file, "wb") as decrypted_file:
                    decrypted_file.write(contents_decryption)
            print("Files decrypted successfully. Congrats, you guessed the key right!")
        else:
            print("Next Time!!!!!! give me bitcoins")
    except FileNotFoundError:
        print("Error: Key file not found.")

def main():
    parser = argparse.ArgumentParser(description="A multi-tool for Caesar Cipher, password strength checking, XOR image encryption/decryption, and file encryption/decryption.")
    
    subparsers = parser.add_subparsers(dest="command")
    
    # Subparser for Caesar Cipher
    caesar_parser = subparsers.add_parser('caesar', help="Encrypt or decrypt text using Caesar Cipher.")
    caesar_parser.add_argument('-e', '--encrypt', type=str, help="Text to encrypt")
    caesar_parser.add_argument('-d', '--decrypt', type=str, help="Text to decrypt")
    caesar_parser.add_argument('-s', '--shift', type=int, required=True, help="Shift value (1 to 26)")

    # Subparser for password strength checking
    password_parser = subparsers.add_parser('password', help="Check the strength of a password.")
    password_parser.add_argument('-p', '--password', required=True, help="Password to check strength.")

    # Subparser for XOR image encryption/decryption
    xor_parser = subparsers.add_parser('xor', help="XOR encrypt/decrypt an image.")
    xor_parser.add_argument('-i', '--input', required=True, help="Path to the input image file.")
    xor_parser.add_argument('-o', '--output', required=True, help="Path to save the output image file.")
    xor_parser.add_argument('-k', '--key', type=int, required=True, help="Key for XOR encryption/decryption.")

    # Subparser for file encryption
    encrypt_parser = subparsers.add_parser('file-encrypt', help="Encrypt all files in the current directory except the script and key files.")
    
    # Subparser for file decryption
    decrypt_parser = subparsers.add_parser('file-decrypt', help="Decrypt all files in the current directory using a provided key.")
    decrypt_parser.add_argument('-k', '--key', required=True, help="Key for decryption.")

    args = parser.parse_args()

    if args.command == 'caesar':
        if args.encrypt:
            encrypted_text = caesar_cipher(args.encrypt, args.shift)
            print(f"The Encrypted Text is: {encrypted_text}")
        elif args.decrypt:
            decrypted_text = caesar_cipher(args.decrypt, -args.shift)
            print(f"The Decrypted Text is: {decrypted_text}")
        else:
            print("You must specify either -e/--encrypt or -d/--decrypt with the text to process.")
    
    elif args.command == 'password':
        check_password_strength(args.password)
    
    elif args.command == 'xor':
        if not os.path.isfile(args.input):
            print(f"Error: The file {args.input} does not exist.")
            return
        
        if args.key < 0 or args.key > 255:
            print("Error: Key must be an integer between 0 and 255.")
            return
        
        xor_encrypt_decrypt(args.input, args.output, args.key)
    
    elif args.command == 'file-encrypt':
        encrypt_files()

    elif args.command == 'file-decrypt':
        decrypt_files(args.key)

if __name__ == "__main__":
    main()
