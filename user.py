import bcrypt

class User:
    def __init__(self) -> None:
        self.user = str(input("Enter a username: "))
        self.salt = bcrypt.gensalt() + bytes(self.user.encode('utf-8'))
        print(self.user.encode('utf-8'))
        print(self.salt)
        self.hashpass = bcrypt.hashpw(str(input("Enter a password: ")).encode('utf8'), bcrypt.gensalt())

    def verifyPass(self, checkPass: str) -> bool:
        return bcrypt.checkpw(checkPass.encode('utf8'), user.hashpass)


user = User()

print(user.verifyPass('password'))