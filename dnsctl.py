#!/usr/bin/env python3
"""Personal DNS: dedicated Docker stack, no changes to existing proxies or DNS."""
import getpass
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tarfile
import time

ROOT = Path('/opt/personal-dns')
AGH = 'adguard/adguardhome:v0.107.79'
NGINX = 'nginx:stable-alpine'


def run(*args, capture=False, **kwargs):
    return subprocess.run(list(args), check=True, text=True,
                          stdout=subprocess.PIPE if capture else None, **kwargs).stdout


def write(path, text, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temp = path.with_name(path.name + '.new')
    with os.fdopen(os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode), 'w', encoding='utf-8') as stream:
        stream.write(text)
    os.chmod(temp, mode)
    os.replace(temp, path)


def save(state):
    write(ROOT / 'state.json', json.dumps(state, indent=2) + '\n')


def load():
    return json.loads((ROOT / 'state.json').read_text())


def domain(value):
    value = value.strip().lower().rstrip('.')
    if len(value) > 200 or '.' not in value or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', p) for p in value.split('.')):
        raise ValueError('Введите домен латиницей, без https://, порта, пути и wildcard.')
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise ValueError('Нужен домен, не IP.')


def free_port(port, host='0.0.0.0'):
    try:
        with socket.socket() as sock:
            sock.bind((host, port))
        return True
    except OSError:
        return False


def pick_port(candidates, host='0.0.0.0'):
    for port in candidates:
        if free_port(port, host):
            return port
    raise RuntimeError('Нет свободного порта из предложенного диапазона.')


def compose(*args, capture=False):
    prefix = ['docker', 'compose']
    if subprocess.run(prefix + ['version'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
        prefix = ['docker-compose']
    return run(*prefix, '-p', 'personal-dns', '-f', str(ROOT / 'compose.json'), *args, capture=capture)


def dependencies(cert_mode):
    if not Path('/etc/debian_version').exists() or not shutil.which('apt-get'):
        raise RuntimeError('Первая версия поддерживает Ubuntu 22.04/24.04 и Debian 12/13, systemd.')
    packages = ['ca-certificates', 'openssl', 'python3-bcrypt']
    if not shutil.which('docker'):
        packages += ['docker.io']
    run('apt-get', 'update')
    run('apt-get', 'install', '-y', *packages)
    if subprocess.run(['docker', 'compose', 'version'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode and not shutil.which('docker-compose'):
        candidate = run('apt-cache', 'policy', 'docker-compose-v2', capture=True)
        package = 'docker-compose-v2' if re.search(r'Candidate:\s+(?!\(none\))\S+', candidate) else 'docker-compose'
        run('apt-get', 'install', '-y', package)
    if cert_mode == 'cloudflare':
        run('apt-get', 'install', '-y', 'certbot', 'python3-certbot-dns-cloudflare')
    run('systemctl', 'start', 'docker')
    run('docker', 'info', capture=True)


def image_digest(tag):
    run('docker', 'pull', tag)
    values = json.loads(run('docker', 'image', 'inspect', tag, '--format', '{{json .RepoDigests}}', capture=True))
    if not values or '@sha256:' not in values[0]:
        raise RuntimeError('Не удалось закрепить digest образа.')
    return values[0]


def configuration(s, password_hash):
    return {
        'schema_version': 34,
        'http': {'address': '0.0.0.0:3000', 'session_ttl': '24h', 'doh': {'insecure_enabled': True}},
        'users': [{'name': 'admin', 'password': password_hash}], 'auth_attempts': 5, 'block_auth_min': 15,
        'language': 'ru', 'theme': 'auto',
        'dns': {'bind_hosts': ['0.0.0.0'], 'port': 53, 'serve_plain_dns': False,
                'upstream_dns': ['https://dns.quad9.net/dns-query', 'https://cloudflare-dns.com/dns-query'],
                'bootstrap_dns': ['9.9.9.9', '1.1.1.1'], 'upstream_mode': 'load_balance',
                'allowed_clients': [s['client_id']], 'ratelimit': 30, 'ratelimit_whitelist': [],
                'cache_enabled': True, 'cache_size': 4194304, 'enable_dnssec': True,
                'use_private_ptr_resolvers': False},
        'tls': {'enabled': True, 'server_name': s['domain'], 'force_https': False,
                'port_https': 0, 'port_dns_over_tls': 853, 'port_dns_over_quic': 0,
                'certificate_path': '/certs/fullchain.pem', 'private_key_path': '/certs/privkey.pem'},
        'querylog': {'enabled': False}, 'statistics': {'enabled': False},
        'filtering': {'protection_enabled': True, 'filtering_enabled': s['filter_ads']},
        'filters': ([{'enabled': True, 'url': 'https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt',
                      'name': 'AdGuard DNS filter', 'id': 1}] if s['filter_ads'] else []),
    }


def nginx_config(s):
    # Only the exact capability URL is exposed. No admin, /control, or setup route.
    return '''events { worker_connections 512; }
http {
  access_log off;
  error_log /dev/stderr crit;
  server_tokens off;
  limit_req_zone $binary_remote_addr zone=dns:10m rate=30r/s;
  resolver 127.0.0.11 valid=10s ipv6=off;
  server {
    listen 8443 ssl;
    server_name DOMAIN;
    ssl_certificate /certs/fullchain.pem;
    ssl_certificate_key /certs/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    client_max_body_size 64k;
    client_body_timeout 10s;
    location = /dns-query/CLIENT {
      limit_except GET POST { deny all; }
      limit_req zone=dns burst=60 nodelay;
      set $dns_backend adguard:3000;
      proxy_pass http://$dns_backend;
      proxy_set_header Host DOMAIN;
      proxy_set_header X-Forwarded-For "";
      proxy_set_header X-Real-IP "";
      proxy_read_timeout 15s;
    }
    location / { return 404; }
  }
}
'''.replace('DOMAIN', s['domain']).replace('CLIENT', s['client_id'])


def compose_config(s):
    logs = {'driver': 'json-file', 'options': {'max-size': '5m', 'max-file': '2'}}
    return {'version': '3.8', 'services': {
        'adguard': {'image': s['adguard_image'], 'restart': 'unless-stopped',
                    'ports': ['0.0.0.0:853:853/tcp'],
                    'volumes': ['./conf:/opt/adguardhome/conf', './work:/opt/adguardhome/work', './certs:/certs:ro'],
                    'logging': logs},
        'https': {'image': s['nginx_image'], 'restart': 'unless-stopped', 'depends_on': ['adguard'],
                  'ports': [f"0.0.0.0:{s['https_port']}:8443/tcp"],
                  'volumes': ['./nginx.conf:/etc/nginx/nginx.conf:ro', './certs:/certs:ro'], 'logging': logs},
    }}


def certbot_args():
    return ['--config-dir', str(ROOT / 'acme/config'), '--work-dir', str(ROOT / 'acme/work'), '--logs-dir', str(ROOT / 'acme/logs')]


def certificate_sources(s):
    if s['cert_mode'] == 'cloudflare':
        base = ROOT / 'acme/config/live/personal-dns'
        return base / 'fullchain.pem', base / 'privkey.pem'
    return Path(s['certificate']), Path(s['private_key'])


def deploy_certificates(s, restart=True):
    certificate, key = certificate_sources(s)
    # Validate names, expiry and key pairing before replacing anything.
    run('openssl', 'x509', '-in', str(certificate), '-noout', '-checkend', '86400', capture=True)
    for name in [s['domain'], s['client_id'] + '.' + s['domain']]:
        run('openssl', 'x509', '-in', str(certificate), '-noout', '-checkhost', name, capture=True)
    context = ssl.create_default_context()
    context.load_cert_chain(str(certificate), str(key))
    run('openssl', 'verify', '-CAfile', '/etc/ssl/certs/ca-certificates.crt', '-untrusted', str(certificate), str(certificate), capture=True)
    write(ROOT / 'certs/fullchain.pem', certificate.read_text())
    write(ROOT / 'certs/privkey.pem', key.read_text())
    if restart:
        compose('exec', '-T', 'https', 'nginx', '-t')
        compose('restart', 'adguard', 'https')


def credentials(s, admin_ip='IP_КОНТЕЙНЕРА'):
    port = '' if s['https_port'] == 443 else ':' + str(s['https_port'])
    return f"""НЕ ПУБЛИКУЙТЕ ЭТОТ БЛОК. Адрес содержит ключ доступа.
Android → Частный DNS: {s['client_id']}.{s['domain']}
DNS-over-TLS: tls://{s['client_id']}.{s['domain']}
DNS-over-HTTPS: https://{s['domain']}{port}/dns-query/{s['client_id']}
Админка: выполните НА СВОЁМ ПК:
  ssh -L 18080:{admin_ip}:3000 root@{s['server_ip']}
Затем откройте http://127.0.0.1:18080
Логин: admin
Начальный пароль: {s['admin_password']}
Если пароль изменили в админке, сохранённый здесь первоначальный пароль устарел.
"""


def show_info(s):
    cid = compose('ps', '-q', 'adguard', capture=True).strip()
    details = json.loads(run('docker', 'inspect', cid, '--format', '{{json .NetworkSettings.Networks}}', capture=True))
    addresses = [n['IPAddress'] for n in details.values() if n.get('IPAddress')]
    if not addresses: raise RuntimeError('Контейнер не имеет IPv4. Проверьте dnsctl status.')
    print(credentials(s, str(ipaddress.IPv4Address(addresses[0]))))


def dns_query():
    return b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01'


def good_answer(data):
    return len(data) >= 12 and data[:2] == b'\x12\x34' and bool(data[2] & 128) and data[3] & 15 == 0 and struct.unpack('!H', data[6:8])[0] > 0


def doctor(s):
    import http.client
    query = dns_query()
    conn = http.client.HTTPSConnection(s['domain'], s['https_port'], timeout=15)
    conn.request('POST', '/dns-query/' + s['client_id'], body=query, headers={'Content-Type': 'application/dns-message'})
    response = conn.getresponse()
    if response.status != 200 or not good_answer(response.read()):
        raise RuntimeError('DoH не вернул корректный DNS-ответ.')
    conn.close()
    conn = http.client.HTTPSConnection(s['domain'], s['https_port'], timeout=15)
    conn.request('GET', '/control/status')
    if conn.getresponse().status != 404:
        raise RuntimeError('Админка не должна быть доступна через публичный HTTPS!')
    conn.close()
    conn = http.client.HTTPSConnection(s['domain'], s['https_port'], timeout=15)
    conn.request('POST', '/dns-query/wrong-client', body=query, headers={'Content-Type':'application/dns-message'})
    if conn.getresponse().status != 404:
        raise RuntimeError('DoH без правильного идентификатора не заблокирован!')
    conn.close()
    def dot(host):
        with socket.create_connection((s['server_ip'], 853), timeout=12) as raw:
            with ssl.create_default_context().wrap_socket(raw, server_hostname=host) as tls:
                tls.sendall(struct.pack('!H', len(query)) + query)
                def exact(n):
                    out = b''
                    while len(out) < n:
                        part = tls.recv(n - len(out))
                        if not part:
                            raise EOFError('DoT закрыл соединение')
                        out += part
                    return out
                size = struct.unpack('!H', exact(2))[0]
                return exact(size)
    if not good_answer(dot(s['client_id'] + '.' + s['domain'])):
        raise RuntimeError('DoT не вернул корректный ответ.')
    try:
        answer = dot(s['domain'])
    except (OSError, EOFError):
        answer = b''
    if good_answer(answer):
        raise RuntimeError('DoT отвечает без идентификатора! Проверьте allowed_clients.')
    print('OK: DoH, DoT, TLS, запрет неизвестного клиента и закрытая публичная админка.')


def install():
    if ROOT.exists():
        raise RuntimeError('Каталог /opt/personal-dns уже существует. Ничего не перезаписано. Используйте dnsctl status/resume; не запускайте установку заново.')
    for target in ['/usr/local/bin/dnsctl', '/etc/systemd/system/personal-dns-renew.service', '/etc/systemd/system/personal-dns-renew.timer']:
        if Path(target).exists():
            raise RuntimeError('Путь уже занят: ' + target + '. Чужие файлы не перезаписываются.')
    print('Личный DNS: Ubuntu/Debian + Docker. Nexus, Caddy, firewall и системный DNS не изменяются.')
    s = {'domain': domain(input('Домен DNS (например dns.example.com): ')),
         'server_ip': str(ipaddress.IPv4Address(input('Публичный IPv4 этого VPS: ').strip())),
         'client_id': secrets.token_hex(16), 'admin_password': secrets.token_urlsafe(24)}
    s['https_port'] = pick_port([443, 8443, 9443])
    if not ipaddress.IPv4Address(s['server_ip']).is_global:
        raise ValueError('Нужен публичный IPv4 VPS.')
    if not free_port(853):
        raise RuntimeError('TCP 853 занят. Для Android Private DNS он обязателен. Освободите его самостоятельно или используйте другой VPS.')
    mode = input('Сертификат: 1 — Cloudflare автоматически, 2 — готовый wildcard [1]: ').strip() or '1'
    if mode not in ['1', '2']:
        raise ValueError('Выберите 1 или 2.')
    s['cert_mode'] = 'cloudflare' if mode == '1' else 'existing'
    token = None
    if mode == '1':
        s['email'] = input('Email для уведомлений Let’s Encrypt: ').strip()
        if not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', s['email']):
            raise ValueError('Некорректный email.')
        token = getpass.getpass('Cloudflare API Token (Zone/DNS/Edit только для нужного домена): ').strip()
        if not re.fullmatch(r'[A-Za-z0-9_-]{20,200}', token):
            raise ValueError('Некорректный формат API Token.')
        print('Будет запрошен сертификат Let’s Encrypt. Условия: https://letsencrypt.org/repository/')
    else:
        s['certificate'] = str(Path(input('Полный путь fullchain.pem: ').strip()).resolve(strict=True))
        s['private_key'] = str(Path(input('Полный путь privkey.pem: ').strip()).resolve(strict=True))
    s['filter_ads'] = input('Включить блокировку рекламы? [нет]: ').strip().lower() in ['да', 'yes']
    print(f"Открываются TCP {s['https_port']} (DoH), 853 (DoT). Порт админки не публикуется; вход через SSH-туннель.")
    print('Будут установлены пакеты apt и два контейнера. Порт 53 и обычный DNS не публикуются.')
    if input('Продолжить и принять условия выпуска сертификата (если выбран Cloudflare)? Введите ДА: ') != 'ДА':
        print('Отменено.'); return
    dependencies(s['cert_mode'])
    if run('docker', 'ps', '-aq', '--filter', 'label=com.docker.compose.project=personal-dns', capture=True).strip():
        raise RuntimeError('Docker-проект personal-dns уже существует. Установка остановлена без его изменения.')
    ROOT.mkdir(mode=0o700)
    save(s)
    write(ROOT / 'dnsctl.py', Path(__file__).read_text(), 0o700)
    write('/usr/local/bin/dnsctl', '#!/bin/sh\nexec /usr/bin/python3 /opt/personal-dns/dnsctl.py "$@"\n', 0o755)
    if token:
        write(ROOT / 'cloudflare.ini', 'dns_cloudflare_api_token = ' + token + '\n')
    resume(s)


def resume(s):
    if s.get('installed'):
        print('Уже установлено. Используйте dnsctl status/doctor/info.'); return
    certificate, key = certificate_sources(s)
    if s['cert_mode'] == 'cloudflare' and not certificate.exists():
        run('certbot', 'certonly', *certbot_args(), '--dns-cloudflare', '--dns-cloudflare-credentials', str(ROOT / 'cloudflare.ini'),
            '--dns-cloudflare-propagation-seconds', '60', '--non-interactive', '--agree-tos', '--email', s['email'],
            '--cert-name', 'personal-dns', '-d', s['domain'], '-d', '*.' + s['domain'])
    deploy_certificates(s, restart=False)
    if not s.get('adguard_image'):
        s['adguard_image'] = image_digest(AGH); save(s)
    if not s.get('nginx_image'):
        s['nginx_image'] = image_digest(NGINX); save(s)
    if not (ROOT / 'conf/AdGuardHome.yaml').exists():
        import bcrypt
        hashed = bcrypt.hashpw(s['admin_password'].encode(), bcrypt.gensalt(12)).decode()
        write(ROOT / 'conf/AdGuardHome.yaml', json.dumps(configuration(s, hashed), indent=2))
    (ROOT / 'work').mkdir(exist_ok=True, mode=0o700)
    write(ROOT / 'nginx.conf', nginx_config(s))
    write(ROOT / 'compose.json', json.dumps(compose_config(s), indent=2))
    compose('config', '--quiet')
    compose('run', '--rm', '--no-deps', 'adguard', '--check-config', '-c', '/opt/adguardhome/conf/AdGuardHome.yaml')
    compose('run', '--rm', '--no-deps', 'https', 'nginx', '-t')
    compose('up', '-d')
    if s['cert_mode'] == 'cloudflare':
        write('/etc/systemd/system/personal-dns-renew.service', '[Unit]\nDescription=Renew Personal DNS certificate\n[Service]\nType=oneshot\nExecStart=/usr/local/bin/dnsctl renew\n')
        write('/etc/systemd/system/personal-dns-renew.timer', '[Unit]\nDescription=Personal DNS certificate renewal\n[Timer]\nOnCalendar=*-*-* 03,15:17:00\nRandomizedDelaySec=3600\nPersistent=true\n[Install]\nWantedBy=timers.target\n')
        run('systemctl', 'daemon-reload'); run('systemctl', 'enable', '--now', 'personal-dns-renew.timer')
    s['installed'] = True; save(s)
    print('\nКонтейнеры запущены. До настройки DNS-записей подключение НЕ готово.')
    print(f"Создайте DNS-only A-записи: {s['domain']} и *.{s['domain']} → {s['server_ip']}.")
    print('В Cloudflare серая тучка, НЕ Proxied. Не добавляйте AAAA без настроенного IPv6.')
    show_info(s)
    print('После распространения DNS: sudo dnsctl doctor. Откройте выбранные TCP-порты в firewall провайдера.')


def main():
    if os.name != 'posix' or os.geteuid() != 0:
        raise RuntimeError('Запустите на Linux от root: sudo dnsctl ...')
    os.umask(0o077)
    command = sys.argv[1] if len(sys.argv) > 1 else input('1 — данные, 2 — состояние, 3 — проверка, 4 — backup: ').strip()
    command = {'1':'info','2':'status','3':'doctor','4':'backup'}.get(command, command)
    if command == 'install':
        install(); return
    s = load()
    if command == 'info': show_info(s)
    elif command == 'status': compose('ps')
    elif command == 'logs': compose('logs', '--tail', '60')
    elif command == 'doctor': doctor(s)
    elif command == 'resume': resume(s)
    elif command == 'restart': compose('restart')
    elif command in ['stop', 'start']: compose(command)
    elif command == 'certificates': deploy_certificates(s)
    elif command == 'renew':
        if s['cert_mode'] != 'cloudflare': raise RuntimeError('В этом режиме обновите исходные PEM и выполните dnsctl certificates.')
        run('certbot', 'renew', *certbot_args(), '--deploy-hook', '/usr/local/bin/dnsctl certificates')
    elif command == 'backup':
        dest = ROOT.parent / ('personal-dns-backup-' + time.strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(3) + '.tar.gz')
        compose('stop')
        try:
            with tarfile.open(dest, 'x:gz') as archive: archive.add(ROOT, arcname='personal-dns')
        finally: compose('start')
        os.chmod(dest, 0o600)
        print(f'Backup с секретами: {dest}. Храните вне GitHub. Команда вызывает короткую остановку DNS.')
    else: raise ValueError('Команды: info, status, logs, doctor, backup, start, stop, restart, resume, renew, certificates')


if __name__ == '__main__':
    try: main()
    except (Exception, KeyboardInterrupt) as exc:
        # Do not print subprocess arguments: endpoints can include a capability ID.
        print('Остановлено: ' + (f'команда завершилась с кодом {exc.returncode}' if isinstance(exc, subprocess.CalledProcessError) else str(exc)), file=sys.stderr)
        print('Данные не удалены. После устранения причины используйте sudo dnsctl resume/status.', file=sys.stderr)
        sys.exit(1)
