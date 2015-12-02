#!/usr/bin/env python
"""
Nessus 6 API

Only does the things we need to do:

 - Authenticate
 - List scans
 - Download scan data
"""

import requests
import time
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger('nessus6api')


class Nessus6API:
    def __init__(self, url=None, username=None, password=None, access_key=None, secret_key=None, verify=True, proxies=None):
        self.session = requests.Session()
        self.url = url
        if self.url.endswith('/'):
            self.url = self.url[:-1]
        self.username = username
        self.password = password
        self.access_key = access_key
        self.secret_key = secret_key
        self.verify = verify
        self.proxies = proxies
        self.is_authenticated = False
        self.token = None
        self.folders = []
        self.login()

    def _send(self, url, data={}, json={}, method='POST'):
        if self.is_authenticated is False:
            self.login()
        if method == 'GET':
            if self.proxies:
                req = self.session.get(url=url, data=data, json=json, verify=self.verify, proxies=self.proxies)
            else:
                req = self.session.get(url=url, data=data, json=json, verify=self.verify)
        elif method == 'POST':
            if self.proxies:
                req = self.session.post(url=url, data=data, json=json, verify=self.verify, proxies=self.proxies)
            else:
                req = self.session.post(url=url, data=data, json=json, verify=self.verify)

        return req

    def login(self):
        self.is_authenticated = False
        self.token = None
        if 'X-Cookie' in self.session.headers:
            self.session.headers.pop('X-Cookie')
        url = "{0}/session".format(self.url)
        if self.username and self.password:
            data = {
                'username': self.username,
                'password': self.password
            }
            res = self.session.post(url, json=data, proxies=self.proxies, verify=self.verify)
            contents = res.json()
            self.token = contents['token']
            self.is_authenticated = True
            self.session.headers.update({'X-Cookie': 'token={0}'.format(self.token)})
        elif self.access_key and self.secret_key:
            self.is_authenticated = True
            self.session.headers.update(
                {'X-ApiKeys': 'accessKey={0}; secretKey={1};'.format(self.access_key, self.secret_key)}
            )
        else:
            raise Exception('No username or API keys provided')

    def get_folders(self):
        url = '{0}/folders'.format(self.url)
        res = self._send(url, method='GET')
        if res.status_code == 200:
            self.folders = res.json()['folders']
        elif res.status_code == 403:
            raise Exception(res.reason)
        else:
            return res
        return self.folders

    def get_scans(self, folder_id=None):
        if folder_id is None:
            url = '{0}/scans'.format(self.url)
        else:
            url = '{0}/scans?folder_id={1}'.format(self.url, folder_id)
        res = self._send(url, method='GET')
        if res.status_code == 200:
            return res.json()['scans']
        else:
            raise Exception(res.reason)

    def scan_export(self, scan_id):
        """This is a bit of a hack, only downloads nessus format where API can do more"""
        url = '{0}/scans/{1}/export'.format(self.url, str(scan_id))
        data = {
            'chapters': None,
            'format': 'nessus'
        }
        res = self._send(url, json=data, method='POST')
        if res.status_code == 200:
            return res.json()['file']
        elif res.status_code == 400:
            raise Exception('Missing parameters')
        elif res.status_code == 404:
            raise Exception('Scan does not exist')
        else:
            raise Exception(res.reason)

    def export_status(self, scan_id, file_id):
        url = '{0}/scans/{1}/export/{2}/status'.format(self.url, scan_id, file_id)
        res = self._send(url, method='GET')
        if res.status_code == 200:
            return res.json()['status']
        elif res.status_code == 404:
            raise Exception('Scan or file does not exist')
        else:
            raise Exception(res.reason)

    def scan_download(self, scan_id, file_id):
        url = '{0}/scans/{1}/export/{2}/download'.format(self.url, scan_id, file_id)
        res = self._send(url, method='GET')
        if res.status_code == 200:
            return res.content
        elif res.status_code == 404:
            raise Exception('Scan or file does not exist')
        else:
            raise Exception(res.reason)

    def report_download(self, scan_id, time_delay=5):
        """Bundles scan_export and scan_download together"""
        file_id = self.scan_export(scan_id)
        status = ''
        count = 0
        while status != 'ready':
            if count > 5:
                raise Exception('Report download timed out')
            status = self.export_status(scan_id, file_id)
            logger.debug('status = {0}'.format(status))
            count += 1
            if status != 'ready':
                time.sleep(time_delay)

        contents = self.scan_download(scan_id, file_id)
        return contents


if __name__ == '__main__':
    from pprint import pprint
    #n = Nessus6API(url='https://localhost:8834', 'username', 'password', verify=False)
    n = Nessus6API(
        url='https://localhost:8834', secret_key='f23a0072b5ce3a701c4105553cf029fa1a8ff0a2f3de91207c006f3bfa71d5a4',
        access_key='492371350d7aadf5220223c6f64733338aa741fc52aada2fcd09b7b8dcaf387d', verify=False
    )

    folders = n.get_folders()
    pprint(folders)

    print("\n\n")
    scans = n.get_scans()
    pprint(scans)

