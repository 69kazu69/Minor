from Blockchain import Blockchain
import os



def main() -> None:
    obj = Blockchain('Genesis Block')
    
    while True:
        data=input('Enter Data: ')
        os.system('clear')

        if data=='':
            print(obj.show())
            obj.makeFile()
            break
        else:
            obj.allHash()
            obj.addBlock(data)
            
            os.system('sleep 0.1')



if __name__ == '__main__':
    main()