from Blockchain import Blockchain
from flask import Flask, jsonify
import os

app = Flask(__name__)


@app.route('/', methods=['GET'])
def main() -> None:
    obj = Blockchain('Genesis Block')
    
    while True:
        data=input('Enter Data: ')
        os.system('clear')

        if data=='':
            print(obj.show())
            obj.makeFile()
            response_data = {'message': 'Form submitted successfully'}
            return jsonify(response_data)
            
        else:
            obj.allHash()
            obj.addBlock(data)
            
            os.system('sleep 0.1')

if __name__ == '__main__':
    app.run(debug=True)