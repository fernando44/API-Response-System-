from flask import Flask, request, jsonify
import requests
import os
import logging
from flask_cors import CORS
from dotenv import load_dotenv
from datetime import datetime

# Carrega variáveis de ambiente do .env
load_dotenv()

app = Flask(__name__)
CORS(app)

# Desabilita os logs padrões do Flask
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

# Configuração de logging personalizado
logging.basicConfig(
    filename='app.log',
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s'
)

# Obtém a API Key do VirusTotal
API_KEY = os.getenv("VT_API_KEY")
if not API_KEY:
    raise Exception("A chave da API não foi definida. Por favor, defina a variável de ambiente VT_API_KEY.")

VT_BASE_URL = "https://www.virustotal.com/api/v3/ip_addresses/"

@app.route('/')
def dashboard():
    return jsonify({
        "message": "Dashboard - Exibição de alertas de segurança",
        "alertas": "Funcionalidade para exibir gráficos e detalhes pendente de integração com o Frontend"
    })

def consultar_virustotal(ip):
    """Consulta o IP na API do VirusTotal"""
    url = f"{VT_BASE_URL}{ip}"
    headers = {"x-apikey": API_KEY}
    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        raise Exception(f"Status {response.status_code} na resposta da API para IP {ip}")
    
    return response.json()

@app.route('/verificar_ip', methods=['POST'])
def verificar_ip():
    data = request.get_json()

    # Suporte a múltiplos IPs
    ips = data.get("ips")
    if ips is None:
        ip = data.get("ip")
        if not ip:
            return jsonify({"error": "Nenhum IP fornecido"}), 400
        ips = [ip]
    elif not isinstance(ips, list):
        ips = [ips]

    resultados = []

    for ip in ips:
        try:
            result = consultar_virustotal(ip)
        except Exception as e:
            logging.error(f"Erro ao consultar VirusTotal para IP {ip}: {str(e)}")
            resultados.append({"ip": ip, "error": str(e)})
            continue

        attributes = result.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        maliciosos = stats.get("malicious", 0)
        suspeitos = stats.get("suspicious", 0)
        inseguros = maliciosos + suspeitos
        seguros = stats.get("harmless", 0)
        as_owner = attributes.get("as_owner", "N/A")

        cert = attributes.get("last_https_certificate", {}).get("subject", {})
        cidade = cert.get("L", "N/A")
        estado = cert.get("ST", "N/A")
        pais = cert.get("C", "N/A")

        alerta = "Inseguro" if inseguros > 2 else "Seguro"

        # Cria log formatado conforme especificado
        ip_cliente = request.remote_addr
        data_str = datetime.now().strftime("%d/%b/%Y %H:%M:%S")
        log_msg = f'{ip_cliente} - - [{data_str}] "POST /verificar_ip HTTP/1.1" IP: {ip} - {alerta} (Inseguros: {inseguros}, Seguros: {seguros})'
        logging.info(log_msg)

        resultados.append({
            "ip": ip,
            "Inseguros": inseguros,
            "Seguros": seguros,
            "cidade": cidade,
            "estado": estado,
            "pais": pais,
            "Gerenciado por": as_owner,
            "alerta": alerta
        })

    return jsonify({"resultados": resultados})

if __name__ == '__main__':
    app.run(debug=True, port=5000)
