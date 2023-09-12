import sqlite3
import bcrypt
import csv
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from getpass import getpass

# Set up the SQLite database
conn = sqlite3.connect('passwords.db')
cursor = conn.cursor()

# Create the table to store passwords
cursor.execute('''CREATE TABLE IF NOT EXISTS passwords (
                    id INTEGER PRIMARY KEY,
                    username TEXT,
                    encrypted_password BLOB,
                    salt BLOB,
                    notes TEXT)''')

# Function to create the master password and store it securely
def create_master_password():
    master_password = getpass("Enter the master password: ")
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(master_password.encode(), salt)
    save_master_password(hashed_password, salt)

# Function to securely store the master password
def save_master_password(hashed_password, salt):
    with open('master_password.txt', 'wb') as file:
        file.write(hashed_password)
    with open('salt.txt', 'wb') as file:
        file.write(salt)

# Function to derive encryption key from a password and salt using PBKDF2
def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password)

# Function to encrypt data using AES
def encrypt_data(data, key):
    cipher = Cipher(algorithms.AES(key), modes.GCM())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return ciphertext, encryptor.tag

# Function to decrypt data using AES
def decrypt_data(ciphertext, key, tag):
    cipher = Cipher(algorithms.AES(key), modes.GCM(tag))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# Function to add a new password to the database
def add_password():
    username = input("Enter the username: ")
    password = getpass("Enter the password: ")
    notes = input("Enter any notes: ")

    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode(), salt)

    cursor.execute("INSERT INTO passwords (username, encrypted_password, salt, notes) VALUES (?, ?, ?, ?)",
                   (username, hashed_password, salt, notes))
    conn.commit()
    print("Password added successfully!")

# Function to retrieve a password from the database
def retrieve_password():
    username = input("Enter the username for which you want to retrieve the password: ")

    cursor.execute("SELECT encrypted_password, salt FROM passwords WHERE username=?", (username,))
    result = cursor.fetchone()

    if result is None:
        print("Password not found!")
        return

    password = getpass("Enter the master password: ")

    with open('salt.txt', 'rb') as file:
        salt = file.read()

    with open('master_password.txt', 'rb') as file:
        hashed_master_password = file.read()

    if bcrypt.checkpw(password.encode(), hashed_master_password):
        key = derive_key(password.encode(), salt)
        decrypted_password = bcrypt.checkpw(result[0], key)
        print(f"Decrypted password for {username}: {decrypted_password}")
    else:
        print("Invalid master password!")

# Function to backup the password database
def backup_database():
    backup_file = input("Enter the name of the backup file: ")
    password = getpass("Enter the backup file password: ")

    with open(backup_file, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['username', 'encrypted_password', 'salt', 'notes'])

        cursor.execute("SELECT * FROM passwords")
        results = cursor.fetchall()

        for row in results:
            encrypted_password = row[2]
            salt = row[3]
            notes = row[4]

            key = derive_key(password.encode(), salt)
            encrypted_data, tag = encrypt_data(encrypted_password, key)
            writer.writerow([row[1], encrypted_data, tag, notes])

    print("Database backup created successfully!")

# Main menu loop
def main_menu():
    while True:
        print("\n===== Password Locker Menu =====")
        print("1. Create master password")
        print("2. Add a password")
        print("3. Retrieve a password")
        print("4. Backup database")
        print("5. Quit")

        choice = input("Enter your choice: ")

        if choice == "1":
            create_master_password()
        elif choice == "2":
            add_password()
        elif choice == "3":
            retrieve_password()
        elif choice == "4":
            backup_database()
        elif choice == "5":
            break
        else:
            print("Invalid choice. Please try again.")

    # Close the database connection
    conn.close()
    print("Exiting Password Locker")

# Run the main menu
main_menu()
