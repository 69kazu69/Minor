import sqlite3, requests, getpass, hashlib, os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from Blockchain import Blockchain

DB_PATH = 'DB/keys_database.db'


def generate_salt():
    return os.urandom(16)

def hash_password(password, salt):
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)

def generate_rsa_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def get_pass_phrase(num=12) -> str:
    url = f"https://random-word-api.herokuapp.com/word?number={num}"
    response = requests.get(url)
    if response.status_code == 200:
        phrase = ' '.join(response.json())
        return phrase
    else:
        return ''

def save_keys_to_sqlite(private_key, public_key, email_id, password) -> str:
    salt = generate_salt()
    phrase = get_pass_phrase()
    security_phrase = hash_password(phrase, salt)

    # Connect to SQLite database
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Create keys table if it doesn't exist
    cursor.execute('''CREATE TABLE IF NOT EXISTS keys
                      (email_id TEXT PRIMARY KEY,
                      private_key BLOB,
                      public_key BLOB,
                      security_phrase BLOB,
                      salt BLOB)''')

    # Serialize the private key
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
    )

    # Serialize the public key
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Insert keys into the table
    cursor.execute("INSERT OR REPLACE INTO keys (email_id, private_key, public_key, security_phrase, salt) VALUES (?, ?, ?, ?, ?)",
                   (email_id, private_key_pem, public_key_pem, security_phrase, salt))

    # Commit changes and close connection
    conn.commit()
    conn.close()
    return phrase

def load_keys_from_sqlite(email_id, password):
    try:
        # Connect to SQLite database
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # Retrieve encrypted keys from the database
        cursor.execute("SELECT private_key, public_key, security_phrase, salt FROM keys WHERE email_id=?", (email_id,))
        row = cursor.fetchone()
        if row is None:
            print("User not found.")
            return None, None

        # Decrypt and deserialize private key
        private_key_pem = row[0]
        private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=password.encode(),
            backend=default_backend()
        )

        # Deserialize public key
        public_key_pem = row[1]
        public_key = serialization.load_pem_public_key(
            public_key_pem,
            backend=default_backend()
        )

        hash_passphrase = row[2]

        salt = row[3]

        # Close connection and return keys
        conn.close()
        return private_key, public_key, hash_passphrase, salt
    except Exception as e:
        print("Error loading keys from SQLite:", e)
        return None, None, None, None

def authenticate_user(private_key, public_key, password):
    try:
        # Encrypt the password with the public key
        encrypted_password = public_key.encrypt(
            password.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        # Decrypt the encrypted password with the private key
        decrypted_password = private_key.decrypt(
            encrypted_password,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        # Check if decrypted password matches the original password
        if decrypted_password == password.encode():
            return True
        else:
            print("Authentication failed: Decrypted password does not match the original password.")
            return False
    except Exception as e:
        print("Authentication failed:", e)
        return False

def encrypt_message(public_key, message):
    try:
        encrypted_message = public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_message
    except Exception as e:
        print("Encryption failed:", e)
        return None

def decrypt_message(private_key, encrypted_message):
    try:
        decrypted_message = private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted_message.decode()
    except Exception as e:
        print("Decryption failed:", e)
        return None

def sign_up():
    email_id = input("Enter user identification: ")
    password = getpass.getpass(f"Enter password to encrypt the key pair for user '{email_id}': ")
    repass = getpass.getpass(f"Re-Enter password to confirm: ")

    if password != repass:
        print('failed')
        return -1

    private_key, public_key = generate_rsa_key()
    phrase = save_keys_to_sqlite(private_key, public_key, email_id, password)
    print(phrase)
    print("RSA key pair generated and saved.")

def sign_in():
    email_id = input("Enter user identification: ")
    password = getpass.getpass(f"Enter password for user '{email_id}': ")
    phrase = getpass.getpass(f"Enter Pass phrase for user '{email_id}': ")
    private_key, public_key, hashpass, salt = load_keys_from_sqlite(email_id, password)

    if private_key is None or public_key is None:
        return 'could not load the key'

    if not authenticate_user(private_key, public_key, password):
        return 'user not found'

    if hash_password(phrase, salt) != hashpass:
        return 'wrong pass phrase'

    return 'login successful'

def authenticate_sign(data, sign, public_key):
    try:
        public_key.verify(
            sign,
            data.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        return False

def polling(data, sign, public_key, private_key):
    if authenticate_sign(data, sign, public_key):
        data = decrypt_message(private_key, data)








# def display_table():
#     try:
#         # Connect to SQLite database
#         conn = sqlite3.connect(DB_PATH)
#         cursor = conn.cursor()

#         # Execute SQL query to select all rows from the table
#         cursor.execute("SELECT * FROM keys")

#         # Fetch all rows
#         rows = cursor.fetchall()

#         # Print column headers
#         print("User ID\tPrivate Key\t\t\t\tPublic Key")
#         print("-" * 80)

#         # Print each row
#         for row in rows:
#             print(row[0], "\t", row[1], "\t", row[2], "\t", row[3], "\t", row[4])

#         # Close connection
#         conn.close()
#     except Exception as e:
#         print("Error displaying table:", e)
# # display_table()