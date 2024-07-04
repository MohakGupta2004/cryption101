# Cryption101

Cryption101 is a versatile Python script that combines multiple functionalities:
1. **Caesar Cipher** for text encryption and decryption.
2. **Password Strength Checker** to evaluate the strength of your passwords.
3. **XOR Image Encryption/Decryption** to securely encrypt and decrypt image files.
4. **File Encryption/Decryption** using symmetric key encryption.

## Features

### Caesar Cipher

Encrypt or decrypt text using the classic Caesar Cipher technique.

#### Usage

python3 cryption101.py caesar -e "Hello World" -s 3
Arguments

    -e, --encrypt: Text to encrypt.
    -d, --decrypt: Text to decrypt.
    -s, --shift: Shift value (1 to 26).

### Password Strength Checker

Check the strength of a password and get recommendations to make it stronger.

### Usage
python3 cryption101.py password -p "YourPassword123!"
Arguments

    -p, --password: Password to check strength.

### XOR Image Encryption/Decryption

Encrypt or decrypt an image using XOR encryption.

### Usage
python3 cryption101.py xor -i path/to/input_image.jpg -o path/to/output_image.jpg -k 123

Arguments

    -i, --input: Path to the input image file.
    -o, --output: Path to save the output image file.
    -k, --key: Key for XOR encryption/decryption (0 to 255).

### File Encryption/Decryption

Encrypt or decrypt all files in the current directory using symmetric key encryption.
File Encryption

Encrypt all files in the current directory except the script and key files.
### Usage

python3 cryption101.py file-encrypt

### File Decryption

Decrypt all files in the current directory using a provided key.
### Usage

python3 cryption101.py file-decrypt -k "randsome"

Arguments

    -k, --key: Key for decryption.

### Installation

    Clone the repository:

git clone https://github.com/MohakGupta2004/cryption101.git

    Navigate to the project directory:

cd cryption101

    Run the script with the desired functionality:

python3 cryption101.py -h

### Examples
### Caesar Cipher

Encrypt the text "Hello World" with a shift of 3:
python3 cryption101.py caesar -e "Hello World" -s 3

Decrypt the text "Khoor Zruog" with a shift of 3:
python3 cryption101.py caesar -d "Khoor Zruog" -s 3

### Password Strength Checker

Check the strength of the password "YourPassword123!":
python3 cryption101.py password -p "YourPassword123!"

### XOR Image Encryption/Decryption

Encrypt an image with key 123:
python3 cryption101.py xor -i path/to/input_image.jpg -o path/to/output_image.jpg -k 123

Decrypt the image with key 123:
python3 cryption101.py xor -i path/to/output_image.jpg -o path/to/decrypted_image.jpg -k 123

### File Encryption

Encrypt all files in the current directory:
python3 cryption101.py file-encrypt

### File Decryption

Decrypt all files in the current directory with the key "randsome":

python3 cryption101.py file-decrypt -k "randsome"

### Contributing

Contributions are welcome! Please open an issue or submit a pull request for any enhancements or bug fixes.
