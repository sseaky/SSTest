#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author: Seaky
# @Date:   2020/8/4 9:26

import argparse
import base64
import logging
import os
import random
import re
import socket
import time
from subprocess import run, PIPE, STDOUT
from urllib import parse

import dns.resolver
import requests
import socks
from speedtest import Speedtest

Pattern_IP = '(?P<ip>((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?))'

SSLOCAL = 'sslocal'
TIMEOUT = 15


def makelog(log=None, console=False):
    if log:
        return log
    fmt = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    log = logging.getLogger('SS')
    log.setLevel(logging.INFO)
    h = logging.StreamHandler()
    h.setLevel(logging.DEBUG)
    h.setFormatter(fmt)
    if console:
        log.addHandler(h)
    return log


def execute(cmd, stdout=PIPE, stderr=STDOUT, encoding='utf-8', shell=False, log=None, *args, **kwargs):
    log = makelog(log)
    if isinstance(cmd, str):
        shell = True
    log.debug(cmd)
    p = run(cmd, stdout=stdout, stderr=stderr, shell=shell, *args, **kwargs)
    if isinstance(p.stdout, bytes):
        p.stdout = p.stdout.decode(encoding)
    if isinstance(p.stderr, bytes):
        p.stderr = p.stderr.decode(encoding)
    return p


def b64decode(s):
    if not s.strip():
        return ''
    if len(s) % 4 != 0:
        s += (4 - len(s) % 4) * '='
    return base64.b64decode(s).decode()


def ss_decode(cipher):
    ss = parse.unquote(cipher)
    data = {'raw': cipher, 'type': 'ss'}
    p1 = '^ss://(?P<cipher>[^#]*)(#(?P<name>.+$))*'
    p2 = '^(?P<pwd_raw>\w+)@(?P<server>[^:]+):(?P<port>\d+)(\?(?P<extra>[^#]+))*'
    p3 = '^(?P<method>[^:]+):(?P<pwd>[^@]+)@(?P<server>[^:]+):(?P<port>\d+)(\?(?P<extra>[^#]+))*'

    m1 = re.search(p1, ss, re.I)
    if not m1:
        return
    data.update(m1.groupdict(''))

    # 有部分加密和完全加密两种方式
    m2 = re.search(p2, data['cipher'], re.I)
    if m2:
        data.update(m2.groupdict(''))
        pwd_raw = b64decode(data['pwd_raw'])
        data['method'], data['pwd'] = pwd_raw.split(':', 1)
    if not data.get('server'):
        m3 = re.search(p3, b64decode(data['cipher']), re.I)
        data.update(m3.groupdict())
    return data


def ssr_decode(cipher):
    # server:server_port:protocol:method:obfs:password/?obfsparam=obfs_param&protoparam=protocol_param&remarks=remarks&group=group
    p1 = '^ssr://(?P<cipher>.*)'
    p2 = '^(?P<server>[^:]+):(?P<port>[^:]+):(?P<protocol>[^:]+):(?P<method>[^:]+):(?P<obfs>[^:]+):(?P<raw_pwd>[^/]+)/\?(?P<extra>.+)'
    p3 = '(?P<key>[^=&]+)=(?P<value>[^=&]*)'
    m1 = re.search(p1, cipher, re.I)
    if not m1:
        return
    s = m1.group('cipher')
    if '_' in s:
        plain1 = '{}?{}'.format(*[b64decode(x) for x in s.split('_')])
    else:
        plain1 = b64decode(m1.group('cipher'))
    data = re.search(p2, plain1, re.I).groupdict('')
    data['pwd'] = b64decode(data['raw_pwd'])
    data['param'] = {}
    if data['extra']:
        for x in re.finditer(p3, data['extra'], re.I):
            data['param'][x.group('key')] = b64decode(x.group('value').replace('-', '+'))
    data['name'] = data['param'].get('remarks', '')
    data['raw'] = cipher
    data['type'] = 'ssr'
    return data


def check_remote_port(server, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    try:
        result = sock.connect((server, int(port)))
        # result = sock.connect_ex((server, int(port)))
        sock.settimeout(None)
        flag = 'open'
    except Exception:
        flag = 'close'
    sock.settimeout(None)
    sock.close()
    return flag


def next_free_port(min_port=50000, max_port=65535, rnd=False):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    port = random.choice(range(min_port, max_port)) if rnd else min_port
    times = max_port - min_port
    while port <= max_port and times > 0:
        try:
            sock.bind(('', port))
            sock.close()
            return port
        except OSError:
            port = random.choice(range(min_port, max_port)) if rnd else port + 1
        times -= 1
    raise IOError('no free ports')


def set_socks_proxy(addr=None, port=None, rdns=True, username=None, password=None,
                    proxytype=socks.PROXY_TYPE_SOCKS5):
    defaultproxy = {'proxytype': proxytype, 'addr': addr, 'port': port, 'rdns': rdns,
                    'username': username, 'password': password}
    socks.setdefaultproxy(**defaultproxy)
    socket.socket = socks.socksocket


def unset_socks_proxy():
    socks.setdefaultproxy(None)
    socket.socket = socks.socksocket


class Connect:
    def __init__(self, data, log=None):
        self.log = makelog(log)
        self.data = data
        self.lport = next_free_port()
        self.geo = False
        pidfile = 'sslocal.pid'
        logfile = 'sslocal.log'
        self.patten_cmd = '{} -s {server} -p {port} -l {lport} -k "{pwd}" -m {method} --pid-file={pidfile} --log-file={logfile} -d {{}}'.format(
            SSLOCAL, lport=self.lport, pidfile=pidfile, logfile=logfile, **self.data['info'])

    def __enter__(self):
        if not self.data['network'].get('status') == 'open':
            return self
        if self.data.get('tunnel_error'):
            return self
        execute(self.patten_cmd.format('stop'))
        cmd = self.patten_cmd.format('start')
        self.data['cmd'] = self.patten_cmd.format('start')
        self.p_start = execute(cmd, log=self.log)
        if self.p_start.returncode != 0:
            self.log.error(self.p_start.stdout.strip())
            self.data['tunnel_error'] = self.p_start.stdout.strip()
        else:
            self.data['tunnel'] = True
            self.data['socks5_proxy'] = 'socks5://127.0.0.1:{}'.format(self.lport)
            self.set_socks_proxy()
            self.get_ip_info()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        unset_socks_proxy()
        cmd = self.patten_cmd.format('stop')
        self.p_stop = execute(cmd, log=self.log)
        self.data['tunnel'] = False

    def set_socks_proxy(self):
        set_socks_proxy('127.0.0.1', self.lport)

    def get_ip_info(self):
        if self.data.get('geo'):
            return
        try:
            d = self.fetch('https://api.ip.sb/geoip', timeout=TIMEOUT).json()
            # 入口与出口是服务器
            if d['ip'] == self.data['info']['server']:
                self.data['info'].update(d)
            else:
                self.data['masque'] = d
                d1 = self.fetch('https://api.ip.sb/geoip/{server}'.format(**self.data['info']), timeout=TIMEOUT).json()
                self.data['info'].update(d1)
            self.data['geo'] = True
            # import pynat
            # print(pynat.get_ip_info(include_internal=True))
        except Exception as e:
            self.log.error(e)

    def fetch(self, url, timeout=TIMEOUT):
        r = requests.get(url, timeout=timeout, verify=True,
                         headers={'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; rv:2.0.1) Gecko/20100101 Firefox/4.0.1'},
                         # proxies={'http': self.data['socks5_proxy'], 'https': self.data['socks5_proxy']}
                         )
        return r


class SSProxy:
    def __init__(self, cipher='', data=None, test='', console=False, log=None):
        self.log = makelog(log=log, console=console)
        self.test = test
        self.data = data if data else {'cipher': cipher, 'network': {}, 'info': {}}
        self.console = console

    def decode(self):
        self.log.info('Processing {}'.format(self.data['cipher']))
        self.log.info('Decoding')
        s = self.data['cipher']
        if re.search('^ss:', s, re.I):
            data = ss_decode(s)
        elif re.search('^ssr:', s, re.I):
            data = ssr_decode(s)
        else:
            data = {}
        if data.get('server') and re.search('[a-z]', data['server'], re.I):
            data['domain'] = data['server']
            data['server'] = dns.resolver.resolve(data['domain'], 'A')[0].address
        self.data['info'].update(data)
        if data:
            self.data['key'] = '{server}:{port}'.format(**data)
        self.func_test()

    def func_test(self):
        if self.test:
            self.test_port()
            self.test_ping()
        for x in self.test.split(','):
            if hasattr(self, 'test_{}'.format(x)):
                getattr(self, 'test_{}'.format(x))()

    def test_port(self):
        if self.data.get('info'):
            self.log.info('Testing remote server port.')
            self.data['network']['status'] = check_remote_port(server=self.data['info']['server'],
                                                               port=self.data['info']['port'])

    def test_ping(self):
        if self.data['network'].get('status') != 'open':
            return
        if self.data.get('info'):
            self.log.info('Testing ping.')
            cmd = 'ping -q -c 10 -i 0.2 -W 1 {server}'.format(**self.data['info'])
            result = os.popen(cmd).read()
            m = re.search(
                '(?P<ping_loss>\d+)%[\s\S]+?(?P<rtt_min>[\d\.]+)/(?P<rtt_avg>[\d\.]+)/(?P<rtt_max>[\d\.]+)/(?P<rtt_mdev>[\d\.]+)',
                result)
            self.data['network'].update(m.groupdict())

    def _test_web(self, name, url, timeout=TIMEOUT):
        if self.data['network'].get('port') == 'close':
            return
        if 'web' not in self.data:
            self.data['web'] = {}
        with Connect(self.data, log=self.log) as con:
            if self.data.get('tunnel'):
                start = time.time()
                self.log.info('Fetching {}'.format(name))
                try:
                    r = con.fetch(url=url, timeout=timeout)
                    self.data['web'][name] = round(time.time() - start, 3)
                except Exception as e:
                    self.log.error(e)
                    self.data['web'][name] = -1
        return self.data['web'].get(name, -1)

    def test_google(self):
        return self._test_web('google', 'https://www.google.com/')

    def test_youtube(self):
        return self._test_web('youtube', 'https://www.youtube.com/')

    def test_speed(self):
        with Connect(self.data, log=self.log) as con:
            if not self.data.get('tunnel'):
                return
            con.set_socks_proxy()
            self.log.info('Testing speed.')
            speedtest = Speedtest(timeout=TIMEOUT)
            self.log.info('Retrieving best server.')
            speedtest.get_best_server()
            self.log.info('Testing download.')
            speedtest.download(threads=1)
            self.log.info('Testing upload.')
            speedtest.upload(threads=1)
            d = {x: speedtest.results.server[x] for x in ['name', 'sponsor', 'url', 'country']}
            d.update({x: round(getattr(speedtest.results, x), 2) for x in ['ping', 'download', 'upload']})
            self.data['speedtest'] = d

    def display(self):
        if self.data.get('info'):
            indent = ' ' * 2
            keys = ['type', 'name', 'domain', 'server', 'port', 'status', 'pwd', 'method', 'country', 'longitude',
                    'latitude', 'isp', 'cmd']
            s = '\n{}Info\n'.format(indent)
            for k in keys:
                if k in self.data['info']:
                    s += '{}{:<12}{}\n'.format(indent * 2, k, self.data['info'][k])
            if 'param' in self.data['info']:
                for k, v in self.data['info']['param'].items():
                    s += '{}{:<12}{}\n'.format(indent * 2, k, v)
            if self.data.get('network'):
                s += '{}Network\n'.format(indent)
                for k in ['ping_loss', 'rtt_avg', 'status']:
                    if k in self.data['network']:
                        s += '{}{:<12}{}\n'.format(indent * 2, k, self.data['network'][k])
            if self.data.get('masque'):
                s += '{}Masque\n'.format(indent)
                for k in ['ip', 'country', 'longitude', 'latitude', 'isp']:
                    s += '{}{:<12}{}\n'.format(indent * 2, k, self.data['masque'][k])
            if self.data.get('speedtest'):
                s += '{}Speedtest\n'.format(indent)
                for k in ['name', 'sponsor', 'url', 'country', 'ping', 'download', 'upload']:
                    s += '{}{:<12}{}\n'.format(indent * 2, k, self.data['speedtest'][k])
            if self.data.get('web'):
                s += '{}Web\n'.format(indent)
                for k, v in self.data['web'].items():
                    s += '{}{:<12}{}\n'.format(indent * 2, k, v)
            self.log.info(s)
        else:
            self.log.error('Can not parse.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--cipher', help='ss cipher')
    parser.add_argument('-f', '--file', help='read from file')
    parser.add_argument('--test', default='', help='google,youtube,speed')
    args = parser.parse_args()
    log = makelog(console=True)
    if args.file:
        items = re.findall('ssr*://[^\s,]+', open(args.file).read(), re.I)
    elif args.cipher:
        items = [args.cipher]
    for cipher in items:
        ss = SSProxy(console=True, cipher=cipher, test=args.test, log=log)
        ss.decode()
        ss.display()
