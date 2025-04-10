# 🔒 API Response System

Este projeto é uma API em Flask que consulta IPs na VirusTotal, classifica-os como seguros ou inseguros, e atualiza arquivos de whitelist e blacklist automaticamente.

## 🚀 Funcionalidades

- Consulta de IPs na API do VirusTotal
- Classificação automática com base em detecções maliciosas e suspeitas
- Atualização de arquivos `WhiteList.txt` e `blacklist.txt`
- Suporte a múltiplos IPs em uma única requisição
- Logging detalhado de requisições
- Otimização com `ThreadPoolExecutor` para desempenho paralelo

## 📁 Estrutura de Pastas

```
.
├── app.py                  # Ponto de entrada da aplicação Flask
├── .env                   # Contém sua chave da API VirusTotal
├── requirements.txt       # Dependências do projeto
├── WhiteList.txt          # Lista de IPs permitidos
├── blacklist.txt          # Lista de IPs maliciosos
├── api/
│   ├── __init__.py
│   └── routes.py
├── services/
│   └── virustotal_service.py
├── utils/
│   ├── list_utils.py
│   └── logging_utils.py
```

## ⚙️ Pré-requisitos

- Python 3.8+
- Uma conta no [VirusTotal](https://virustotal.com) para obter sua API Key

## 🔧 Instalação

1. Clone o repositório:

```bash
git clone https://github.com/seu-usuario/API-Response-System.git
cd API-Response-System
```

2. Crie um ambiente virtual (opcional, mas recomendado):

```bash
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate   # Windows
```

3. Instale as dependências:

```bash
pip install -r requirements.txt
```

4. Crie um arquivo `.env` com sua chave da API:

```env
VT_API_KEY=sua_chave_da_api_aqui
```

## ▶️ Execução

```bash
python app.py
```

A API estará disponível em `http://localhost:5000`.

## 📡 Endpoints

### `POST /verificar_ip`

**Corpo da requisição (JSON):**

```json
{
  "ips": ["8.8.8.8", "1.1.1.1"]
}
```

**Resposta:**

```json
{
  "resultados": [
    {
      "ip": "8.8.8.8",
      "Inseguros": 0,
      "Seguros": 90,
      "cidade": "N/A",
      "estado": "N/A",
      "pais": "US",
      "Gerenciado por": "Google LLC",
      "alerta": "Seguro"
    }
  ]
}
```

## 🧠 Observações

- IPs com mais de 2 detecções maliciosas ou suspeitas são considerados **inseguros**.
- Esses IPs são adicionados à `blacklist.txt`, exceto se já estiverem na whitelist.
- Logging é salvo no arquivo `app.log`.

## 🛠️ Futuras Melhorias

- Interface web para gestão de listas
- Integração com firewalls automaticamente
- Suporte a domínios além de IPs

## 📄 Licença

Este projeto é open-source, sinta-se à vontade para modificar e contribuir.