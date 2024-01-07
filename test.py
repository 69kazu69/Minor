from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding


class AsymmetricUserAuthentication:
    def __init__(self):
        # Generate a key pair for the server (replace this with a secure key pair in a real application)
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()

        # Dummy user data (replace with a database in a real application)
        self.users = {'user1': self.public_key, 'user2': self.public_key}

    def sign_message(self, message):
        signature = self.private_key.sign(
            message.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature


    def authenticate_user(self, username, message, signature):
        # Check if the username exists
        if username in self.users:
            # Verify the signature using the stored public key
            public_key = self.users[username]
            try:
                public_key.verify(
                    signature,
                    message.encode('utf-8'),
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                print(f"Authentication successful! Welcome, {username}.")
                return True
            except Exception as e:
                print(f"Signature verification failed: {e}")
        else:
            print("Username not found. Authentication failed.")
        return False



# Example usage
authenticator = AsymmetricUserAuthentication()

# Message to be signed and verified
message = "Hello, user1!"

# Server signs the message
signature = authenticator.sign_message(message)

# Replace the stored public key with the actual user public key in a real application
authenticator.users['user1'] = authenticator.public_key

# Test case: Successful authentication
authenticator.authenticate_user('user1', message, signature)

# Test case: Incorrect username
authenticator.authenticate_user('nonexistent_user', message, signature)

# Test case: Incorrect signature
authenticator.authenticate_user('user2', message, b'incorrect_signature')

print(authenticator.users['user1'])
