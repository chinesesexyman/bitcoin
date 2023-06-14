# encoding=utf8

import sys
from utilx import varIntDecode, intDecode
from rpc_tools import client
from ordi_parser import proc


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
    return data[2*l:], script


def tx_decoder(tx: str, parse_ord=False):
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
    """
    ord逻辑
    if witness.stack[-1].startswith(0x50):
        # support in the future
        script = witness.stack[0:-2]
    else:
        script = witness.stack[0:-1]
    """
    if segwit:
        for i in range(inputCnt):
            print('input %d segwit:' % i)
            tx, segwitCnt = varIntParser(tx, 'segwit count')
            script_stack = []
            for j in range(segwitCnt):
                tx, seg = segwitParser(tx)
                script_stack.append(seg)
            # 解析ordi协议
            if parse_ord:
                if script_stack[-1].startswith('50'):
                    script = ''.join(script_stack[:-2])
                else:
                    script = ''.join(script_stack[:-1])
                proc(script)

    locktime = tx[:8]
    print('locktime: %s(%d)' % (locktime, intDecode(locktime)))
    tx = tx[8:]
    assert len(tx) == 0
    


if __name__ == '__main__':
    tx = client.getrawtransaction(sys.argv[1])['result']['hex']
    tx_decoder(tx, parse_ord=True)
