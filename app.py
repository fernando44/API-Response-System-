from flask import Flask, jsonify, render_template
from flask_cors import CORS
from dotenv import load_dotenv
import os
import logging

# Carrega variáveis de ambiente do .env
load_dotenv()

# Inicializa o app Flask com pastas personalizadas
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.join(BASE_DIR, 'web', 'python-web-app', 'templates')
STATIC_DIR = os.path.join(BASE_DIR, 'web', 'python-web-app', 'static')

app = Flask(__name__, template_folder=TEMPLATE_DIR, static_folder=STATIC_DIR)
CORS(app)

# Configuração do logger
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

logging.basicConfig(
    filename='app.log',
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s'
)

# Validação da chave da API
API_KEY = os.getenv("VT_API_KEY")
if not API_KEY:
    raise Exception("A chave da API não foi definida. Por favor, defina a variável de ambiente VT_API_KEY.")

# Rota principal para carregar o dashboard HTML
@app.route('/')
def dashboard():
    return render_template('index.html')

# Rota para retornar o conteúdo dos logs
@app.route('/logs')
def logs():
    try:
        with open('app.log', 'r', encoding='utf-8') as f:
            conteudo = f.read()
        return conteudo, 200, {'Content-Type': 'text/plain; charset=utf-8'}
    except Exception as e:
        return f"Erro ao ler logs: {e}", 500

# Registra o blueprint da rota /verificar_ip
from routes.verificar_ip import verificar_ip_bp
app.register_blueprint(verificar_ip_bp)

# Inicializa o servidor Flask
if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True, port=5000)
