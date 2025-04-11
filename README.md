# 🔒 API Response System

This project is a Flask-based API that queries IPs using VirusTotal, classifies them as safe or unsafe, and automatically updates the blacklist file.

## 🚀 Features

- IP query using the VirusTotal API  
- Automatic classification based on malicious and suspicious detections  
- Updates `blacklist.txt` automatically  
- Supports multiple IPs in a single request  
- Detailed logging  
- Optimized with `ThreadPoolExecutor` for parallel performance  

## 📁 Project Structure

```
.
├── app.py                 # Flask application entry point
├── .env                   # Contains your VirusTotal API key
├── requirements.txt       # Project dependencies
├── WhiteList.txt          # Allowed IP list
├── blacklist.txt          # Malicious IP list
├── routes/
│   └── verificar_ip.py
├── services/
│   └── virustotal.py
├── utils/
│   ├── listas.py
│   └── logging_utils.py
```

## ⚙️ Prerequisites

- Python 3.8+
- A [VirusTotal](https://virustotal.com) account to obtain your API key

## 🔧 Installation

1. Clone the repository:

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Create a `.env` file with your API key:

```env
VT_API_KEY=your_api_key_here
```

## ▶️ Running the API

```bash
python3 app.py
```

The API will be available at `http://localhost:5000`.

## 📡 IP Submission

### `POST /verificar_ip`

**Request body (JSON):**

```json
{
  "ips": ["8.8.8.8", "1.1.1.1"]
}
```

**Response:**

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

## 🧠 Notes

- IPs with more than 3 malicious or suspicious detections are classified as **unsafe**.  
- Unsafe IPs are added to `blacklist.txt`, unless they are already in the whitelist or their managing organization is whitelisted.  
- Logs are saved to `app.log` and generated for every POST interaction.

## 🛠️ Future Improvements

- Web interface for submitting requests and viewing logs  
- Automatic integration with firewalls