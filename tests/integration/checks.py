#!/usr/bin/env python3
"""Offline command tests: local DNS, HTTP, TLS, sockets, and helper fixtures."""
import http.server
import json
import os
from pathlib import Path
import shutil
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest

BINARY = str(Path(sys.argv.pop(1)).resolve())


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        if self.path == '/slow':
            time.sleep(1.5)
        if self.path in ('/redirect', '/loop-a', '/loop-b'):
            self.send_response(302)
            self.send_header('Location', {'/redirect': '/ok', '/loop-a': '/loop-b', '/loop-b': '/loop-a'}[self.path])
            self.end_headers()
            return
        self.send_response(404 if self.path == '/missing' else 200)
        self.end_headers()
        try:
            self.wfile.write(b'x' * (4096 if self.path == '/large' else 2))
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            pass


class DNS(socketserver.BaseRequestHandler):
    def handle(self):
        query, connection = self.request
        offset = 12
        labels = []
        while query[offset]:
            length = query[offset]
            labels.append(query[offset + 1:offset + 1 + length].decode('ascii'))
            offset += 1 + length
        name = '.'.join(labels)
        end = offset + 5
        kind = struct.unpack('!H', query[offset + 1:offset + 3])[0]
        if name == 'timeout.test':
            return
        rcode = {'missing.test': 3, 'servfail.test': 2}.get(name, 0)
        if kind == 12 and not name.endswith('.arpa'):
            rcode = 3
        records = {
            1: socket.inet_aton('192.0.2.1'),
            28: socket.inet_pton(socket.AF_INET6, '2001:db8::1'),
            5: b'\x05alias\x04test\x00',
            2: b'\x02ns\x04test\x00',
            15: b'\x00\x0a\x04mail\x04test\x00',
            16: b'\x05hello\x05world',
            6: b'\x02ns\x04test\x00\x04host\x04test\x00' + struct.pack('!IIIII', 1, 2, 3, 4, 5),
            257: b'\x00\x05issueissuer.test',
            12: b'\x04host\x04test\x00',
        }
        payload = records.get(kind, b'')
        count = 0 if rcode or name == 'empty.test' else 1
        response = query[:2] + struct.pack('!HHHHH', 0x8180 | rcode, 1, count, 0, 0) + query[12:end]
        if count:
            response += b'\xc0\x0c' + struct.pack('!HHIH', kind, 1, 120, len(payload)) + payload
        connection.sendto(response, self.client_address)


class Checks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.directory = Path(cls.temp.name)
        cls.http = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        cls.dns = socketserver.ThreadingUDPServer(('127.0.0.1', 0), DNS)
        cls.servers = [cls.http, cls.dns]
        for server in cls.servers:
            threading.Thread(target=server.serve_forever, daemon=True).start()
        cls.url = f'http://127.0.0.1:{cls.http.server_port}'
        cls.dns_address = f'127.0.0.1:{cls.dns.server_address[1]}'
        cls.openssl = shutil.which('openssl')
        cls.secure = []
        if cls.openssl:
            for label, days, san in [('valid', 365, 'IP:127.0.0.1,DNS:localhost'),
                                     ('soon', 2, 'IP:127.0.0.1,DNS:localhost'),
                                     ('wrong', 365, 'DNS:wrong.test')]:
                cert, key = cls.directory / f'{label}.pem', cls.directory / f'{label}.key'
                subprocess.run([cls.openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                                '-keyout', str(key), '-out', str(cert), '-days', str(days),
                                '-subj', '/CN=localhost', '-addext', f'subjectAltName={san}'],
                               check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(cert, key)
                server.socket = context.wrap_socket(server.socket, server_side=True)
                cls.servers.append(server)
                threading.Thread(target=server.serve_forever, daemon=True).start()
                cls.secure.append((f'https://127.0.0.1:{server.server_port}', str(cert)))
            # Issue an explicitly expired leaf under the trusted local fixture CA.
            (cls.directory / 'index').write_text('')
            (cls.directory / 'serial').write_text('1000\n')
            config = cls.directory / 'ca.conf'
            config.write_text(f'''[ca]
default_ca=fixture
[fixture]
database={cls.directory}/index
serial={cls.directory}/serial
new_certs_dir={cls.directory}
certificate={cls.directory}/valid.pem
private_key={cls.directory}/valid.key
default_md=sha256
policy=policy
[policy]
commonName=supplied
[leaf]
subjectAltName=IP:127.0.0.1,DNS:localhost
''')
            subprocess.run([cls.openssl, 'req', '-new', '-key', str(cls.directory / 'valid.key'),
                            '-subj', '/CN=expired.localhost', '-out', str(cls.directory / 'expired.csr')],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run([cls.openssl, 'ca', '-batch', '-config', str(config), '-extensions', 'leaf',
                            '-in', str(cls.directory / 'expired.csr'), '-out', str(cls.directory / 'expired.pem'),
                            '-startdate', '20200101000000Z', '-enddate', '20210101000000Z'],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cls.directory / 'expired.pem', cls.directory / 'valid.key')
            server.socket = context.wrap_socket(server.socket, server_side=True)
            cls.servers.append(server)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            cls.secure.append((f'https://127.0.0.1:{server.server_port}', str(cls.directory / 'valid.pem')))

    @classmethod
    def tearDownClass(cls):
        for server in cls.servers:
            server.shutdown()
            server.server_close()
        cls.temp.cleanup()

    def run_netx(self, *args, expected=0, env=None):
        result = subprocess.run([BINARY, *map(str, args)], capture_output=True, text=True, timeout=20, env=env)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        return result

    def report(self, *args, expected=0, env=None):
        result = self.run_netx(*args, '--json', expected=expected, env=env)
        report = json.loads(result.stdout)
        self.assertEqual(report['schema_version'], 1)
        self.assertEqual(report['exit_code'], expected)
        self.assertEqual(result.stderr, '')
        return report['results']

    def test_help_and_validation(self):
        for command in ['dns', 'http', 'tls', 'diagnose', 'check', 'tcp', 'ports', 'ping', 'trace']:
            with self.subTest(command=command):
                self.assertIn('Usage: netx', self.run_netx(command, '--help').stdout)
                self.run_netx(command, '--unknown', expected=2)
                if command != 'ports':
                    self.run_netx(command, expected=2)
        for args in [('http', 'file:///etc/passwd'), ('http', self.url, '--timeout', '0'),
                     ('tcp', 'localhost', '--ports', '80,'), ('tcp', 'localhost', '--ports', '65536'),
                     ('ping', 'localhost', '--count', '0'), ('trace', 'localhost', '--max-hops', '0'),
                     ('ports', '--port', '0'), ('http', self.url, '-4', '-6')]:
            self.run_netx(*args, expected=2)

    def test_dns_all_types(self):
        expected = {'A': '192.0.2.1', 'AAAA': '2001:db8::1', 'CNAME': 'alias.test',
                    'MX': '10 mail.test', 'NS': 'ns.test', 'TXT': '"hello" "world"',
                    'SOA': 'ns.test host.test 1 2 3 4 5', 'CAA': '0 issue "issuer.test"', 'PTR': 'host.test'}
        for kind, answer in expected.items():
            with self.subTest(kind=kind):
                host = '192.0.2.1' if kind == 'PTR' else 'fixture.test'
                report = self.report('dns', host, '--type', kind, '--server', self.dns_address)[0]
                self.assertEqual(report['details']['record_1'], answer + '  TTL 120s')
        reports = self.report('dns', 'fixture.test', '--compare', self.dns_address + ',' + self.dns_address)
        self.assertEqual(len(reports), 2)
        self.report('dns', '2001:db8::1', '--type', 'PTR', '--server', self.dns_address)

    def test_dns_errors(self):
        for name, reason in [('missing.test', 'NXDOMAIN'), ('servfail.test', 'SERVFAIL'),
                             ('empty.test', 'No records'), ('timeout.test', 'timeout')]:
            with self.subTest(name=name):
                result = self.report('dns', name, '--server', self.dns_address, '--timeout', '1', expected=1)[0]
                self.assertIn(reason, result['summary'])

    def test_http_status_redirects_and_limits(self):
        report = self.report('http', self.url + '/ok')[0]
        self.assertEqual(report['details']['status'], '200')
        for key in ['dns', 'connect', 'tls', 'first_byte', 'total']:
            self.assertIn(key, report['details'])
        report = self.report('http', self.url + '/redirect')[0]
        self.assertIn('302', report['details']['redirect_chain'])
        self.assertIn('200', report['details']['redirect_chain'])
        self.report('http', self.url + '/missing', expected=1)
        for path, options, reason in [('/loop-a', [], 'loop'),
                                      ('/redirect', ['--max-redirects', '0'], 'limit'),
                                      ('/large', ['--max-body', '8'], 'body'),
                                      ('/slow', ['--timeout', '1'], 'timed out')]:
            report = self.report('http', self.url + path, *options, expected=1)[0]
            self.assertIn(reason, report['summary'].lower())

    def test_tcp_and_ports(self):
        port = self.http.server_port
        self.report('tcp', '127.0.0.1', '--ports', str(port), '-4')
        report = self.report('ports', '--port', str(port))[0]
        self.assertTrue(any(f':{port} ' in value for value in report['details'].values()))
        with socket.create_connection(('127.0.0.1', port)):
            report = self.report('ports', '--port', str(port), '--established')[0]
            self.assertTrue(any('ESTABLISHED' in value for value in report['details'].values()))
        with socket.socket() as reserved:
            reserved.bind(('127.0.0.1', 0))
            self.report('tcp', '127.0.0.1', '--ports', str(reserved.getsockname()[1]), '-4', expected=1)

    def test_tcp_ipv6(self):
        try:
            server = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            server.bind(('::1', 0))
            server.listen()
        except OSError as error:
            self.skipTest(f'IPv6 unavailable: {error}')
        try:
            self.report('tcp', '[::1]', '--ports', str(server.getsockname()[1]), '-6')
        finally:
            server.close()

    def test_tls(self):
        if not self.openssl:
            self.skipTest('openssl fixture generator not installed')
        url, ca = self.secure[0]
        report = self.report('tls', url, '--ca-file', ca, '--chain')[0]
        self.assertEqual(report['details']['hostname_match'], 'PASS')
        self.assertEqual(report['details']['trust_chain'], 'PASS')
        self.assertGreater(int(report['details']['days_left']), 300)
        self.assertIn('chain_0_Cert', report['details'])
        self.report('tls', url, expected=1)
        self.report('http', url, '--ca-file', ca)
        url, ca = self.secure[1]
        self.assertIn('expires', self.report('tls', url, '--ca-file', ca, expected=3)[0]['summary'])
        url, ca = self.secure[2]
        self.report('tls', url, '--ca-file', ca, expected=1)
        url, ca = self.secure[3]
        report = self.report('tls', url, '--ca-file', ca, expected=1)[0]
        self.assertIn('expired', report['summary'])

    def test_diagnose_dependencies(self):
        report = self.report('diagnose', self.url, expected=3)
        self.assertEqual([step['check'] for step in report], ['DNS', 'TCP', 'TLS', 'HTTP', 'CONCLUSION'])
        self.assertEqual(report[2]['status'], 'SKIPPED')
        with socket.socket() as reserved:
            reserved.bind(('127.0.0.1', 0))
            report = self.report('diagnose', f'https://127.0.0.1:{reserved.getsockname()[1]}', expected=1)
        self.assertEqual(report[1]['status'], 'FAIL')
        self.assertEqual(report[2]['status'], 'SKIPPED')
        self.assertEqual(report[3]['status'], 'SKIPPED')
        if self.openssl:
            url, ca = self.secure[0]
            self.report('diagnose', url, '--ca-file', ca)
            self.assertIn('CONCLUSION', self.run_netx('check', url, '--ca-file', ca).stdout)
            report = self.report('diagnose', url, expected=1)
            self.assertEqual(report[2]['status'], 'FAIL')
            self.assertEqual(report[3]['status'], 'SKIPPED')

    def test_ping_fallback_and_trace_helpers(self):
        helper = self.directory / 'helpers'
        helper.mkdir(exist_ok=True)
        ping = helper / 'ping'
        ping.write_text("#!/bin/sh\necho 'ping: socket: Operation not permitted'\nexit 2\n")
        ping.chmod(0o755)
        env = {**os.environ, 'PATH': str(helper)}
        report = self.report('ping', '127.0.0.1', '--port', self.http.server_port, '--count', '1', expected=3, env=env)[0]
        self.assertIn('TCP fallback', report['details']['method'])
        self.assertIn('jitter_stddev_ms', report['details'])
        report = self.report('trace', '127.0.0.1', expected=3, env=env)[0]
        self.assertEqual(report['status'], 'SKIPPED')
        trace = helper / 'traceroute'
        trace.write_text("#!/bin/sh\necho '1 127.0.0.1 0.1 ms'\n")
        trace.chmod(0o755)
        self.report('trace', '127.0.0.1', env=env)
        trace.write_text("#!/bin/sh\necho '1 192.0.2.1 0.1 ms'\n")
        self.assertEqual(self.report('trace', '127.0.0.1', expected=3, env=env)[0]['status'], 'WARN')
        ping.write_text("#!/bin/sh\necho '1 packets transmitted, 1 received, 0% packet loss'\necho 'rtt min/avg/max/mdev = 0.1/0.2/0.3/0.1 ms'\n")
        report = self.report('ping', '127.0.0.1', '--count', '1', env=env)[0]
        self.assertEqual(report['details']['latency_mean_ms'], '0.2')


if __name__ == '__main__':
    unittest.main()
