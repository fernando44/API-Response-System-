from flask import Flask, request, jsonify
import requests
from flask_cors import CORS  # Permite requisições do frontend

app = Flask(__name__)
CORS(app)  # Permite que o frontend acesse esse backend

API_KEY = "aaaaa"  # Substitua pela sua API Key do VirusTotal

@app.route('/verificar_ip', methods=['POST'])
def verificar_ip():
    data = request.get_json()
    ip = data.get("ip")

    if not ip:
        return jsonify({"error": "Nenhum IP fornecido"}), 400

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": API_KEY}

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        result = response.json()
        analysis_stats = result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        
        maliciosos = analysis_stats.get("malicious", 0)
        suspeitos = analysis_stats.get("suspicious", 0)
        seguros = analysis_stats.get("harmless", 0)
        
        return jsonify({
            "ip": ip,
            "malicious": maliciosos,
            "suspicious": suspeitos,
            "harmless": seguros,
            "total_checks": sum(analysis_stats.values())
        })
    else:
        return jsonify({"error": "Falha na requisição ao VirusTotal", "status": response.status_code}), 500

if __name__ == "__main__":
    app.run(debug=True, port=5000)
