import bcrypt
import sqlite3
import re

DB_PATH = "DB/project.db"

class DB:
    def __init__(self, mail, name, hashpw, salt) -> None:

        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()

        cur.execute("CREATE TABLE IF NOT EXISTS users (email TEXT NOT NULL PRIMARY KEY, username TEXT NOT NULL, hashpass TEXT NOT NULL, salt TEXT NOT NULL)")
        cur.execute("INSERT INTO users (email, username, hashpass, salt) VALUES (?, ?, ?, ?)", (mail, name, hashpw, salt))

        conn.commit()
        cur.close()
        conn.close()



class User:
    def login(self) -> None:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()

        login_info = [str(input("Enter email address: ")),
                      str(input("Enter username: ")),
                      str(input("Enter password: "))]
        
        cur.execute("SELECT hashpass, salt FROM users WHERE email = ? AND username = ? LIMIT 1", (login_info[0], login_info[1]))

        result = cur.fetchone()
        if result == None:
            print('User not Found.')
        else:
            self.hashpass, self.salt = result

            if bcrypt.hashpw(login_info[2].encode('utf8'), self.salt) == self.hashpass:
                self.email = login_info[0]
                self.user = login_info[1]
                print('login successfull...')
            else:
                print('Wrong Password...')
            
        cur.close()
        conn.close()

    def signup(self) -> None:
        self.mail = str(input("Enter a email: "))
        if re.match(r"[^@]+@[^@]+\.[^@]+", self.mail):
            self.user = str(input("Enter username: \n"))
            self.salt = bcrypt.gensalt() + bytes(self.user.encode('utf8')) + bytes(self.mail.encode('utf8'))
            self.hashpass = bcrypt.hashpw(str(input("Enter a password: ")).encode('utf8'), self.salt)
            self.db=DB(self.mail, self.user, self.hashpass, self.salt)
        else:
            print('invalid email address...')

    def verifyPass(self, checkPass: str) -> bool:
        return bcrypt.checkpw(checkPass.encode('utf8'), user.hashpass)



while True:

    response = input("0. Login\n1. Create User\n2. Verify Password\n3. Show DB\n4. exit\n")
    user = User()

    if response == '0':
        user.login()

    elif response == '1':
        user.signup()

    elif response == '2':
        try:
            print(user.verifyPass(str(input("Enter the password to verify...\n"))))
        except:
            print("User Not Created.\nCreate a User first...")

    elif response == '3':
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()

        cur.execute("SELECT * FROM users")
        print(cur.fetchall())

        cur.close()
        conn.close()

    elif response == '4':
        print("exiting...")
        break
    
    else:
        print('invalid response')