import logging
from datetime import datetime
from flask import request

def configurar_logging():
    # Desabilita os logs padrões do Flask
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)

    logging.basicConfig(
        filename='app.log',
        level=logging.INFO,
        format='%(asctime)s %(levelname)s: %(message)s'
    )

def registrar_log(ip, as_owner, alerta, inseguros, seguros, status_extra):
    ip_cliente = request.remote_addr
    data_str = datetime.now().strftime("%d/%b/%Y %H:%M:%S")

    log_msg = f'{ip_cliente} - - [{data_str}] "POST /verificar_ip HTTP/1.1" IP: {ip} ({as_owner}) - {alerta} (Inseguros: {inseguros}, Seguros: {seguros})'
    if status_extra:
        log_msg += f' {status_extra}'

    logging.info(log_msg)
