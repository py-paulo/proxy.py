# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import json
import logging
import urllib.request

from typing import Optional

from ..common.flag import flags
from ..common.utils import build_http_response
from ..http.parser import HttpParser
from ..http.codes import httpStatusCodes
from ..http.proxy import HttpProxyBasePlugin

logger = logging.getLogger(__name__)

flags.add_argument(
    '--rest-api-url',
    type=str,
    default='http://localhost:8000',
    help='Default: http://localhost:8000. REST Api URL.'
)


def HTTP_request(url: str, data: dict) -> bool:
    params = json.dumps(data).encode('utf8')
    req = urllib.request.Request(url, data=params,
                                 headers={'content-type': 'application/json', 'User-Agent': 'proxy.py'})
    try:
        response = urllib.request.urlopen(req)
    except urllib.error.URLError as err:
        logger.critical('unable to replicate log in "%s". %s' % (url, err))
        return False

    response = json.loads(response.read().decode('utf-8', errors='ignore'))
    if response.get('code') == 200:
        return True

    return False


def convert(data):
    def __convert(data):
        if isinstance(data, bytes):  return data.decode('utf-8')
        if isinstance(data, dict):   return dict(map(__convert, data.items()))
        if isinstance(data, tuple):  return list(map(__convert, data))
        return data
    data = __convert(data)
    new_data = {}
    for key, val in data.items():
        if isinstance(val, list) or isinstance(val, tuple):
            new_data[key] = val[-1]
    return new_data


class ReplyLogApiPlugin(HttpProxyBasePlugin):
    """Replicate logs by sending to REST Api."""

    def before_upstream_connection(
            self, request: HttpParser) -> Optional[HttpParser]:
        return request

    def handle_client_request(
            self, request: HttpParser) -> Optional[HttpParser]:
        
        ip_addr = self.client.addr
        host = request.host.decode('utf-8', errors='ignore')
        if not host:
            if b'host' in request.headers:
                host = request.header(b'host')
        encoded_headers = request.headers
        headers = convert(encoded_headers)
        body = None # request.body
        path = request.path.decode('utf-8', errors='ignore')
        method = request.method.decode('utf-8', errors='ignore')

        req = {
            'ip': ip_addr,
            'host': host,
            'headers': headers,
            'body': body,
            'path': path,
            'method': method
        }

        HTTP_request(self.flags.rest_api_url, req)

        return request

    def handle_upstream_chunk(self, chunk: memoryview) -> memoryview:
        return chunk

    def on_upstream_connection_close(self) -> None:
        pass
