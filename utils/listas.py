import os

WHITELIST_FILE = 'WhiteList.txt'
BLACKLIST_FILE = 'blacklist.txt'

def carregar_listas():
    whitelist = set()
    blacklist = set()

    if os.path.exists(WHITELIST_FILE):
        with open(WHITELIST_FILE, 'r', encoding='utf-8') as f:
            whitelist = {line.strip() for line in f if line.strip()}

    if os.path.exists(BLACKLIST_FILE):
        with open(BLACKLIST_FILE, 'r', encoding='utf-8') as f:
            blacklist = {line.strip() for line in f if line.strip()}

    return whitelist, blacklist

def adicionar_blacklist(ip):
    with open(BLACKLIST_FILE, 'a', encoding='utf-8') as f:
        f.write(ip + '\n')

def verificar_listas(ip, as_owner, whitelist, blacklist):
    if ip in whitelist:
        return "esta na Whitelist"
    elif as_owner in whitelist:
        return "Owner esta na Whitelist"
    elif ip in blacklist:
        return "Ja esta na blacklist"
    else:
        return "adicionado na blacklist"