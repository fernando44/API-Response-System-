import requests
import os

API_KEY = os.getenv("VT_API_KEY", "SUA_CHAVE_AQUI")
BASE_URL = "https://www.virustotal.com/api/v3/ip_addresses/"

def consultar_virustotal(ip):
    url = f"{BASE_URL}{ip}"
    headers = {
        "x-apikey": API_KEY
    }

    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        raise Exception(f"Erro na consulta do IP {ip}: {response.status_code} - {response.text}")

    return response.json()
