# encoding=utf8

import sys
from utilx import varIntDecode, intDecode
from rpc_tools import client


def varIntParser(data, desc):
    l, n = varIntDecode(data)
    print('%s: %s(%d)' % (desc, data[0:l*2], n))
    return data[l*2:], n


def inputParser(data):
    txid = data[:64]
    print('txid: %s' % txid)
    data = data[64:]
    idx = data[:8]
    print('index: %s(%d)' % (idx, intDecode(idx)))
    data = data[8:]
    data, l = varIntParser(data, 'unlocking script size')
    script = data[:2*l]
    print('unlocking script: %s' % script)
    data = data[2*l:]
    sequence = data[0:8]
    print('sequence: %s' % sequence)
    return data[8:]


def outputParser(data):
    amount = data[:16]
    print('amount: %s(%d)' % (amount, intDecode(amount)))
    data = data[16:]
    data, l = varIntParser(data, 'locking script size')
    script = data[:2*l]
    print('locking script: %s' % script)
    return data[2*l:]


def segwitParser(data):
    data, l = varIntParser(data, 'witness script size')
    script = data[:2*l]
    print('witness script: %s' % script)
    return data[2*l:]


def tx_decoder(tx: str):
    version = tx[0:8]
    print('version: %s' % version)
    tx = tx[8:]

    segwit = False
    if tx[0:2] == '00':
        segwit = True
        # 见证隔离交易
        marker = tx[0:2]
        flag = tx[2:4]
        print('marker: %s' % marker)
        print('flag: %s' % flag)
        tx = tx[4:]
    
    # 输入
    tx, inputCnt = varIntParser(tx, 'input count')
    for idx in range(inputCnt):
        tx = inputParser(tx)

    # 输出
    tx, outputCnt = varIntParser(tx, 'output count')
    for idx in range(outputCnt):
        tx = outputParser(tx)
    
    # segwit
    if segwit:
        for i in range(inputCnt):
            print('input %d segwit:' % i)
            tx, segwitCnt = varIntParser(tx, 'segwit count')
            for j in range(segwitCnt):
                tx = segwitParser(tx)

    locktime = tx[:8]
    print('locktime: %s(%d)' % (locktime, intDecode(locktime)))
    tx = tx[8:]
    assert len(tx) == 0
    


if __name__ == '__main__':
    # tx = client.getrawtransaction(sys.argv[1])['result']['hex']
    tx = '010000000001015bef9fdf786aad950a8f2827c9406ea4f7e314555f062dc92384945096efeb5c0000000000ffffffff0130d9f5050000000022512033f3b7af97c516ef0cff6dc43fba0162c947b6b3c2062e100e97da61af8fd9c903402ec49a70f2e30b4fb6e0a3649ca1f17e64d98be2f9242018935b6bca0feca2f125fbaebfc0fc3a3a9b6c9f2f288559d5bfc3ee357fa9b1ce10b5c321b517f7477b20c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5ac0063036f7264010118746578742f706c61696e3b636861727365743d7574662d3800357b2270223a226272632d3230222c226f70223a226d696e74222c227469636b223a2263727364222c22616d74223a2231303030227d6821c0c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee500000000'
    tx_decoder(tx)
