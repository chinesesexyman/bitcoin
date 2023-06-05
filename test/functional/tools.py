# encoding=utf8

import sys

def intEncode(n: int, bytes: int) -> str:
    """little endian
    bytes: length of bytes
    return: hex string
    """
    s = hex(n)[2:].zfill(bytes * 2)
    ls = [s[i*2:i*2+2] for i in range(bytes)]
    ls.reverse()
    return ''.join(ls)


def intDecode(data: str) -> int:
    """little endian
    data: hex string
    """
    if data.startswith('0x'):
        data = data[2:]
    ls = [data[i*2:i*2+2] for i in range(int(len(data)/2))]
    ls.reverse()
    return int(''.join(ls), base=16)


def varIntEncode(n: int) -> str:
    """int to VarInt
    n: >= 0
    return: binary_str, hex_str
    每字节第一比特表示下一字节是否属于当前数据 1-属于 0-不属于
    剩下7字节存储一组数据
    小端存储
    """
    if n < 0:
        raise
    i = 0
    while n > 127:
        seg = '1' + bin(n % 128)[2:].zfill(7)  # exclude binary prefix
        i = (i << 8) + int(seg, base=2)
        n = n >> 7
    seg = '0' + bin(n)[2:].zfill(7)
    i = (i << 8) + int(seg, base=2)
    return hex(i)[2:].zfill(2)


def varIntDecode(data: str) -> tuple[int, int]:
    """parse data start with varInt
    data: hex data start with varInt
    return: varInt length, varInt value
    """
    if data.startswith('0x'):
        data = data[2:]
    l = 0
    seg = []
    while data[2*l] >= '8':
        seg.append(data[2*l:2*l+2])
        l = l + 1
    n = int(data[2*l:2*l+2], base=16)
    l = l + 1
    for i in reversed(seg):
        n = (n << 7) + int(i, base=16) - 128
    return l, n

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
    tx_decoder(sys.argv[1])
