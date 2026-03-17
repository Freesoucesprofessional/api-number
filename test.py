import requests



url = "https://api-number.onrender.com/search/number"

headers = {

    "access_token": "ChooseAStrongPassword123",

    "Content-Type": "application/json"

}

payload = {

    "query": "919949871879"

}



response = requests.post(url, json=payload, headers=headers)

print(response.json())