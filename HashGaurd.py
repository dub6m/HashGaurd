import pathlib, os, secrets, base64, getpass
import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# Generate salts: These are random bits added to the password before it is hashed to make it harder to crack
# We'll be using the secrets module instead of random cause it generates more secure values
def generate_salts(size):
    # Generate salt the length of 'size'
    return secrets.token_bytes(size)

# From the password and salts let's derive a key
def derive_key(salt, password):
    # Read about the Scrypt algo to grasp this more
    # The scrypt algo uses salt, cpu cost parameter (n), memory cost parameter (r), parallelization parameter (p)
    # & output length (length) to generate the key.
    '''As mentioned in the documentation, n, r, and p can adjust the computational and
    memory cost of the Scrypt algorithm. RFC 7914 recommends r=8, p=1, where the
    original Scrypt paper suggests that n should have a minimum value of 2**14 for
    interactive logins or 2**20 for more sensitive files; you can check the
    documentation for more information'''
    kdf = Scrypt(salt = salt, length = 32, n = 2**14, r = 8, p = 1)
    return kdf.derive(password.encode())

# Let's make a function that loads the previously generated salt
def load_salts():
    # Load salt from salt.salt
    # The content of the salt is a sequence of bytes aka binary data
    # Therefore the salt is read as binary given the 'rb' specified
    return open("salt.salt", "rb").read()

# Handles the generating, saving & loading of salts so the salt and password can be used to generate a key
def generate_key(password, salt_size, load_salt, save_salt):
    if load_salt: # Means salt exists and can be loaded
        salt = load_salts()
    elif save_salt: # Salt doesn't exist... Can be generated and saved
        salt = generate_salts(salt_size)
        with open("salt.salt", "wb") as salt_file: # "wb" meaning write as binary
            salt_file.write(salt) # Writes salts as binary into salt_file

    # Generate the key from the salt and the password
    derived_key = derive_key(salt, password)

    # Encode it using Base64 and return it
    return base64.urlsafe_b64encode(derived_key)

# Handles the encryption of files
def encrypt(filename, key):
    # Given filename in str and key in bytes
    f = Fernet(key)

    with open(filename, "rb") as file:
        # Read all file data
        file_data = file.read()

    # Encrypt file data
    encrypted_data = f.encrypt(file_data)
    print(f"[*] Encrypting {filename}")

    with open(filename, "wb") as file:
        # Replace the file data with the encrypted data
        file.write(encrypted_data)

# Handles the decryption of files
def decrypt(filename, key):
    # Given filename in str and key in bytes
    f = Fernet(key)

    with open(filename, "rb") as file:
        # Read the encrypted file data
        encrypted_data = file.read()

    try:
        # Decrypt the file data
        decrypted_data = f.decrypt(encrypted_data)
        print(f"[*] Decrypting {filename}")
    except Exception:
        # Handles cases of invalid password/tokens
        print("[!] Invalid token, most likely the password is incorrect")
        return

    with open(filename, "wb") as file:
        # Replace the encrypted file data with the decrypted data
        file.write(decrypted_data)

# Handles the encryption of folders
def encrypt_folder(foldername, key):
    # If it's a folder, encrypt all files in it
    for child in pathlib.Path(foldername).glob("*"):
        # .glob("*") refers to every file/subfolder in the folder
        if child.is_file():
            # Encrypts child if it's a file
            print(f"[*] Encrypting {child}")
            encrypt(child, key)
        else:
            # If child is a folder, run the folder through the encrypt_folder function till no folders are left
            encrypt_folder(child, key)

# Handles the decryption of folders
def decrypt_folder(foldername, key):
    # If it's a folder, encrypt all files in it
    for child in pathlib.Path(foldername).glob("*"):
        # .glob("*") refers to every file/subfolder in the folder
        if child.is_file:
            # Decrypt child if it's a file
            print(f"[*] Decrypting {child}")
            decrypt(child, key)
        else:
            # If child is a folder, run the folder through the decrypt_folder function till no folders are left
            decrypt_folder(child, key)

print("HASHGAURD")
print("(1) Encrypt file || (2) Decrypt file")
print("(3) Encrypt folder || (4) Decrypt folder")
action = input("Choose program mode: ")
action_dir = input("Enter file name/folder dir: ")
password = input("Enter password: ")

if action == "1":
    encrypt(action_dir, generate_key(password, 16, False, True))
elif action == "2":
    decrypt(action_dir, generate_key(password, 16, False, True))
elif action == "3":
    encrypt_folder(action_dir, generate_key(password, 16, False, True))
elif action == "4":
    decrypt_folder(action_dir, generate_key(password, 16, True, False))
else:
    print("Invalid input.")
    print("Terminating...")
