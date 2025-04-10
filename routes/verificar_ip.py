from flask import Blueprint, request, jsonify
import logging
from concurrent.futures import ThreadPoolExecutor
from services.virustotal import consultar_virustotal
from utils.listas import verificar_listas, carregar_listas, adicionar_blacklist
from datetime import datetime
import os

max_threads = int(os.getenv("MAX_THREADS", 10))

verificar_ip_bp = Blueprint('verificar_ip', __name__)

@verificar_ip_bp.route('/verificar_ip', methods=['POST'])
def verificar_ip():
    data = request.get_json()

    ips = data.get("ips")
    if ips is None:
        ip = data.get("ip")
        if not ip:
            return jsonify({"error": "Nenhum IP fornecido"}), 400
        ips = [ip]
    elif not isinstance(ips, list):
        ips = [ips]

    def processar_ip(ip):
        try:
            result = consultar_virustotal(ip)
        except Exception as e:
            logging.error(f"Erro ao consultar VirusTotal para IP {ip}: {str(e)}")
            return {"ip": ip, "error": str(e)}

        attributes = result.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        maliciosos = stats.get("malicious", 0)
        suspeitos = stats.get("suspicious", 0)
        inseguros = maliciosos + suspeitos
        seguros = stats.get("harmless", 0)
        as_owner = attributes.get("as_owner", "N/A").strip()

        cert = attributes.get("last_https_certificate", {}).get("subject", {})
        cidade = cert.get("L", "N/A")
        estado = cert.get("ST", "N/A")
        pais = cert.get("C", "N/A")

        alerta = "Inseguro" if inseguros > 3 else "Seguro"
        status_extra = ""

        if alerta == "Inseguro":
            whitelist, blacklist = carregar_listas()
            status_extra = verificar_listas(ip, as_owner, whitelist, blacklist)

            if status_extra == "adicionado na blacklist":
                adicionar_blacklist(ip)

        # Log personalizado
        data_str = datetime.now().strftime("%d/%b/%Y %H:%M:%S")
        log_msg = f"[{data_str}] IP: {ip} ({as_owner}) - {alerta} (Inseguros: {inseguros}, Seguros: {seguros})"
        if status_extra:
            log_msg += f' {status_extra}'
        logging.info(log_msg)

        return {
            "ip": ip,
            "Inseguros": inseguros,
            "Seguros": seguros,
            "cidade": cidade,
            "estado": estado,
            "pais": pais,
            "Gerenciado por": as_owner,
            "alerta": alerta
        }

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        resultados = list(executor.map(processar_ip, ips))

    return jsonify({"resultados": resultados})
