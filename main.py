from Blockchain import Blockchain
from flask import Flask, jsonify, request
import os

app = Flask(__name__)


@app.route('/sample', methods=['POST'])
def main() -> None:
    obj = Blockchain('Genesis Block')
    json_data = request.json
    data = json_data.get('data')
    for i in data:
        obj.addBlock(i)
    print(obj.show())
    obj.makeFile()
    response_data = {'message': 'Form submitted successfully'}
    return jsonify(response_data)
if __name__ == '__main__':
    app.run(debug=True)
