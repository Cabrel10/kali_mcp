
import requests

url = "https://165.210.32.134/owa/auth.owa"
payload = {
    "destination": "https://165.210.32.134/owa",
    "flags": "4",
    "forcedownlevel": "0",
    "username": "asdfghjkl",
    "password": "password",
    "isUtf8": "1"
}

# Disable SSL warnings and verification
requests.packages.urllib3.disable_warnings()
response = requests.post(url, data=payload, verify=False)

print(response.text)
