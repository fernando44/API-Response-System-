from flask import Flask, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
import os
import logging

load_dotenv()# Carrega variáveis de ambiente do .env

app = Flask(__name__)
CORS(app)

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

logging.basicConfig(
    filename='app.log',
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s'
)


API_KEY = os.getenv("VT_API_KEY")# Verifica a chave da API
if not API_KEY:
    raise Exception("A chave da API não foi definida. Por favor, defina a variável de ambiente VT_API_KEY.")

@app.route('/logs')
def logs():
    try:
        with open('app.log', 'r', encoding='utf-8') as f:
            conteudo = f.read()
        return conteudo, 200, {'Content-Type': 'text/plain; charset=utf-8'}
    except Exception as e:
        return f"Erro ao ler logs: {e}", 500

@app.route('/')
def dashboard():
    return jsonify({"message": "API 1.0"})

from routes.verificar_ip import verificar_ip_bp
app.register_blueprint(verificar_ip_bp)

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True, port=5000)
