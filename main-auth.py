from auth import sign_up, sign_in, hash_password, load_keys_from_sqlite, getpass, authenticate_user, encrypt_message, decrypt_message

def main():
    try:
        # sign_up()
        sign_in()


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