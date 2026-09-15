"""Linux/Docker integration test. Uses a disposable certificate only in this test."""
import importlib.util
import json
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import tempfile
import time
import bcrypt

spec = importlib.util.spec_from_file_location('dnsctl', Path(__file__).parents[1] / 'dnsctl.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


def run(*args, **kwargs):
    return subprocess.run(list(args), check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs).stdout


with tempfile.TemporaryDirectory(prefix='personal-dns-smoke-') as temp:
    root = Path(temp)
    for folder in ['certs', 'conf', 'work']: (root / folder).mkdir()
    # CA-like test cert is explicitly trusted only by the test client.
    cert = root / 'certs/fullchain.pem'; key = root / 'certs/privkey.pem'
    run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
        '-subj', '/CN=dns.example.test', '-addext', 'subjectAltName=DNS:dns.example.test,DNS:*.dns.example.test',
        '-keyout', str(key), '-out', str(cert))
    s = dict(domain='dns.example.test', client_id='a'*32, filter_ads=False,
             adguard_image=m.AGH, nginx_image=m.NGINX, https_port=m.pick_port(range(19443,19500)))
    tls_port = m.pick_port(range(19853,19900))
    config = m.compose_config(s)
    config['services']['adguard']['ports'] = [f'127.0.0.1:{tls_port}:853/tcp']
    config['services']['https']['ports'] = [f"127.0.0.1:{s['https_port']}:8443/tcp"]
    (root / 'compose.json').write_text(json.dumps(config))
    (root / 'nginx.conf').write_text(m.nginx_config(s))
    (root / 'conf/AdGuardHome.yaml').write_text(json.dumps(m.configuration(s, bcrypt.hashpw(b'test-password-only',bcrypt.gensalt()).decode())))
    command = ['docker','compose','-p','personal-dns-smoke','-f',str(root/'compose.json')]
    def compose(*args): return run(*command,*args)
    try:
        compose('pull')
        compose('run','--rm','--no-deps','adguard','--check-config','-c','/opt/adguardhome/conf/AdGuardHome.yaml')
        compose('run','--rm','--no-deps','https','nginx','-t')
        compose('up','-d')
        query = root / 'query.bin'; query.write_bytes(m.dns_query())
        def doh(route):
            output = root / 'response.bin'
            code = run('curl','--silent','--show-error','--noproxy','*','--max-time','15',
                       '--cacert',str(cert),'--resolve',f"{s['domain']}:{s['https_port']}:127.0.0.1",
                       '--header','Content-Type: application/dns-message','--data-binary','@'+str(query),
                       '--output',str(output),'--write-out','%{http_code}',f"https://{s['domain']}:{s['https_port']}{route}").decode()
            return code, output.read_bytes()
        for attempt in range(20):
            try:
                code, data = doh('/dns-query/'+s['client_id'])
                if code == '200' and m.good_answer(data): break
            except subprocess.CalledProcessError: pass
            time.sleep(1)
        else: raise AssertionError('DoH lookup failed')
        for route in ['/control/status', '/', '/dns-query', '/dns-query/unknown']:
            assert doh(route)[0] == '404', route
        context = ssl.create_default_context(cafile=str(cert))
        def dot(name):
            with socket.create_connection(('127.0.0.1',tls_port),timeout=3) as raw:
                with context.wrap_socket(raw,server_hostname=name) as tls:
                    q=m.dns_query();tls.sendall(struct.pack('!H',len(q))+q)
                    def receive(n):
                        data=b''
                        while len(data)<n:
                            chunk=tls.recv(n-len(data))
                            if not chunk: raise EOFError()
                            data+=chunk
                        return data
                    size=struct.unpack('!H',receive(2))[0]
                    return receive(size)
        assert m.good_answer(dot(s['client_id']+'.'+s['domain']))
        try: denied=dot(s['domain'])
        except (OSError,EOFError): denied=b''
        assert not m.good_answer(denied), 'Anonymous DoT must not resolve'
        print('PASS: images/config, DoH, DoT, unknown-client rejection, no public admin')
    except Exception:
        print(compose('logs','--tail','40').decode())
        raise
    finally:
        compose('down')
