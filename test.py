import requests



url = "http://127.0.0.1:8000/search/number"

headers = {

    "access_token": "MY_SECRET_PASSWORD_123",

    "Content-Type": "application/json"

}

payload = {

    "query": "919949871879"

}



response = requests.post(url, json=payload, headers=headers)

print(response.json())