import hashlib
import datetime as date
import json
import string
import random



class Block:
    def __init__(self, index: int, timestamp: str, data: str, previousHash: str):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previousHash = previousHash
        self.nonce = self.calculateNonce()

    def calculateNonce(self) -> str:
        difficulty = 5
        nonce = 0

        while True:
            sha = hashlib.sha256()
            sha.update(str(self.index).encode('utf-8') +
                       str(self.timestamp).encode('utf-8') +
                       str(self.data).encode('utf-8') +
                       str(self.previousHash).encode('utf-8') +
                       str(nonce).encode('utf-8'))
            
            # if sha.hexdigest()[:difficulty] == self.previousHash[-difficulty:]:
            if sha.hexdigest()[:difficulty] == '0' * difficulty:
                self.hash = sha.hexdigest()
                return nonce
            else:
                nonce += 1
        


class Blockchain:
    def __init__(self, name) -> None:
        self.chain = [Block(0, date.datetime.now(), name, ''.join(random.choices(string.digits, k=64)))]
        
    def getLatestBlock(self) -> Block:
        return self.chain[-1]

    def addBlock(self, data) -> None:
        newBlock = Block((self.getLatestBlock().index+1), date.datetime.now(), str(data), self.getLatestBlock().hash)
        self.chain.append(newBlock)

    def show(self) -> str:
        output = '['
        for n in range(len(self.chain)):
            output += '{"Index":"' + str(self.chain[n].index) + '","Timestamp":"' + str(self.chain[n].timestamp) + '","Previous_Hash":"' + self.chain[n].previousHash + '","Hash":"' + self.chain[n].hash + '","Data":"' + str(self.chain[n].data) + '","Nonce":"' + str(self.chain[n].nonce) + '"}'
            if n < (len(self.chain)-1):
                output += ','
        output += ']'

        json_object = json.loads(output)
        json_formatted_str = json.dumps(json_object, indent=4)
        return json_formatted_str
    
    def makeFile(self) -> None:
        f = open("Dev/DB/output.json", "w")
        f.write(self.show())
        f.close()

    
    def allHash(self) -> str:
        for i in range(len(self.chain)):
            print(f"index[{i}] : " + self.chain[i].hash)

    
    def checkChain(self) -> int:
        for n in range(len(self.chain)):
            sha = hashlib.sha256()

            sha.update(str(self.chain[n].index).encode('utf-8') +
                    str(self.chain[n].timestamp).encode('utf-8') +
                    str(self.chain[n].data).encode('utf-8') +
                    str(self.chain[n].previousHash).encode('utf-8') +
                    str(self.chain[n].nonce).encode('utf-8'))
            
            if sha.hexdigest() != self.chain[n].hash:
                return self.chain[n].index
            
        return -1


    def isConsistent(self, n) -> None:
            print("index :" + str(n))
            print("stored :" + self.chain[n].hash)
            print("checked :" + self.checkChain(n) + "\n")

            if self.chain[n].hash != self.checkChain(n):
                print("Failed at :" + str(n))