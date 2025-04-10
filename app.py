from flask import Flask, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
import os
import logging

# Carrega variáveis de ambiente do .env
load_dotenv()

# Criação da aplicação Flask
app = Flask(__name__)
CORS(app)

# Desabilita logs padrões do Flask
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

# Configuração de logging personalizado
logging.basicConfig(
    filename='app.log',
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s'
)

# Verifica a chave da API
API_KEY = os.getenv("VT_API_KEY")
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

# Rota simples de teste
@app.route('/')
def dashboard():
    return jsonify({"message": "API 1.0"})

# Importa as rotas depois da criação do app
from routes.verificar_ip import verificar_ip_bp
app.register_blueprint(verificar_ip_bp)

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True, port=5000)
