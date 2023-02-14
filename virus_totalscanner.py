import hashlib
import requests

def get_file_hash(filename):
    sha256 = hashlib.sha256()
    with open(filename, 'rb') as f:
        while True:
            data = f.read(65536)
            if not data:
                break
            sha256.update(data)
    return sha256.hexdigest()

def is_malicious(file_hash, api_key):
    headers = {
        "x-apikey": api_key
    }
    params = {
        "hash": file_hash
    }
    response = requests.get("https://www.virustotal.com/api/v3/files/{}".format(file_hash), headers=headers, params=params)
    if response.status_code == 200:
        data = response.json()
        return data["data"]["attributes"]["last_analysis_stats"]["malicious"] > 0
    else:
        return False

if __name__ == '__main__':
    filename = input("Enter the filename to scan: ")
    file_hash = get_file_hash(filename)
    api_key = "4183b312ef60e44cf941d741240523ac93f6006482e2834564f6f221cb772bdc"
    if is_malicious(file_hash, api_key):
        print("Malicious file detected.")
    else:
        print("File is not malicious.")

