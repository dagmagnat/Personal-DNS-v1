import importlib.util
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('dnsctl', Path(__file__).parents[1] / 'dnsctl.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def fixture():
    return dict(domain='dns.example.com', client_id='a'*32, filter_ads=False,
                adguard_image='adguard/adguardhome@sha256:'+'a'*64,
                nginx_image='nginx@sha256:'+'b'*64, https_port=8443,
                server_ip='8.8.8.8', admin_password='test-not-secret')


class ProjectTests(unittest.TestCase):
    def test_domain_validation(self):
        self.assertEqual(m.domain(' DNS.Example.COM. '), 'dns.example.com')
        for bad in ['localhost', '127.0.0.1', 'https://dns.test', '*.dns.test', 'dns.test;evil', 'dns.test/hi', 'a..test', '-a.test', 'a_'*150+'.test']:
            with self.subTest(bad=bad), self.assertRaises(ValueError): m.domain(bad)

    def test_no_open_resolver(self):
        c = m.configuration(fixture(), 'hash')
        self.assertFalse(c['dns']['serve_plain_dns'])
        self.assertEqual(c['dns']['allowed_clients'], ['a'*32])
        self.assertEqual(c['tls']['port_dns_over_quic'], 0)
        self.assertFalse(c['querylog']['enabled'])

    def test_only_encrypted_ports_published(self):
        services = m.compose_config(fixture())['services']
        self.assertEqual(services['adguard']['ports'], ['0.0.0.0:853:853/tcp'])
        self.assertEqual(services['https']['ports'], ['0.0.0.0:8443:8443/tcp'])
        self.assertNotIn('network_mode', services['adguard'])
        self.assertNotIn('privileged', services['adguard'])

    def test_proxy_does_not_expose_admin(self):
        config = m.nginx_config(fixture())
        self.assertIn('location = /dns-query/' + 'a'*32, config)
        self.assertIn('location / { return 404; }', config)
        self.assertIn('access_log off', config)
        self.assertIn('resolver 127.0.0.11', config)
        self.assertNotIn('location /control', config)

    def test_filter_is_optional(self):
        s = fixture()
        self.assertEqual(m.configuration(s, 'hash')['filters'], [])
        s['filter_ads'] = True
        self.assertEqual(len(m.configuration(s, 'hash')['filters']), 1)

    def test_port_conflict(self):
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            self.assertFalse(m.free_port(sock.getsockname()[1], '127.0.0.1'))
        with patch.object(m, 'free_port', side_effect=[False, True]):
            self.assertEqual(m.pick_port([443, 8443]), 8443)

    def test_dns_message_validation(self):
        query = m.dns_query()
        self.assertFalse(m.good_answer(query))
        reply = bytearray(query); reply[2] |= 128; reply[7] = 1
        self.assertTrue(m.good_answer(reply))
        reply[3] |= 5
        self.assertFalse(m.good_answer(reply))

    def test_atomic_write(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / 'dir/state.json'
            m.write(target, 'one'); m.write(target, 'two')
            self.assertEqual(target.read_text(), 'two')
            self.assertFalse(target.with_name('state.json.new').exists())

    def test_info_formats(self):
        s = fixture()
        self.assertIn('https://dns.example.com:8443/dns-query/', m.credentials(s))
        s['https_port'] = 443
        self.assertNotIn(':443', m.credentials(s))
        self.assertIn('ssh -L 18080:172.20.0.2:3000', m.credentials(s, '172.20.0.2'))


if __name__ == '__main__': unittest.main()
