# encoding=utf8

import sys
import json
import requests

# RPC_URL = 'https://btc.getblock.io/18ff5dc8-276a-4e88-bd2f-97e5fa05f251/mainnet/'
RPC_URL = 'http://127.0.0.1:18443'
RPC_USER = 'test'
RPC_PASSWORD = 'test'


class CLIENT(object):
    """连接标准节点客户端"""

    def __init__(self, url, user='', password='', server_name='') -> None:
        self.url = url
        self.user = user
        self.password = password
        self.server_name = server_name

    def post(self, body):
        if self.user and self.password:
            return requests.post(self.url, auth=(self.user, self.password), json=body)
        else:
            return requests.post(self.url, json=body)

    def sendrawtransaction(self, data):
        body = {
            "jsonrpc": "1.0",
            "id": self.server_name,
            "method": "sendrawtransaction",
            "params": [data]
        }
        resp = self.post(body)
        return json.loads(resp.content)
    
    def getrawtransaction(self, data):
        body = {
            "jsonrpc": "1.0",
            "id": self.server_name,
            "method": "getrawtransaction",
            "params": [data, True]
        }
        resp = self.post(body)
        return json.loads(resp.content)

# client object
client = CLIENT(RPC_URL, user=RPC_USER, password=RPC_PASSWORD)


if __name__ == '__main__':
    attr = sys.argv[1]
    func = client.__getattribute__(attr)
    res = func(*sys.argv[2:])
    print(res)
