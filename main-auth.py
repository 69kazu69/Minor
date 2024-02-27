from auth import sign_up, sign_in, hash_password, load_keys_from_sqlite, getpass, authenticate_user, encrypt_message, decrypt_message

def main():
    try:
        # sign_up()
        # sign_in()
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


        # # Encrypt and sign a message
        # message = "Hello, this is a secret message!"
        # encrypted_message = encrypt_message(public_key, message)
        # if encrypted_message is not None:
        #     print("Encrypted message:", encrypted_message)

        # # Decrypt and authenticate the message
        # decrypted_message = decrypt_message(private_key, encrypted_message)
        # if decrypted_message is not None:
        #     print("Decrypted message:", decrypted_message)
        
    except Exception as e:
        print("An error occurred:", e)

if __name__ == "__main__":
    main()