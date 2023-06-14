# encoding=utf8
"""
OP_FALSE
OP_IF
    OP_PUSH "ord"
    OP_1
    OP_PUSH "text/plain;charset=utf-8"
    OP_0
    OP_PUSH data(<=520)
    ...
    OP_PUSH data(<=520)
OP_ENDIF
"""

# op_false op_if b'ord' bytes.fromhex('01') 
# 0063036f72640101
MARK = '00' + '63' + '03' + '6f7264' + '01' + '01'


def little_endian_hex2int(s: str):
    """小端16进制转10进制"""
    if len(s) % 2 != 0:
        raise
    ls = [s[2 * i:2 * i + 2] for i in range(len(s) // 2)]
    ret = 0
    for i in reversed(ls):
        ret = ret * 256 + int(i, base=16)
    return ret


def type_detector(s: str):
    """ord文件格式"""
    start = s.index(MARK) + len(MARK)
    l = int(s[start:start + 2], base=16)
    start = start + 2
    content = s[start:start + l * 2]
    print('Content-Type: %s(%s)' % (content, bytes.fromhex(content).decode('utf8')))
    return s[start + l * 2:]


def get_bytes(s: str):
    """ord文件内容"""
    s = s[2:]
    ret = ''
    while True:
        if s[:2] == '68':  # OP_ENDIF
            break
        elif s[:2] < '4c':
            l = little_endian_hex2int(s[:2])
            ret += s[2:2 + l * 2]
            s = s[2 + l * 2:]
        elif s[:2] == '4c':  # OP_PUSHDATA1
            l = little_endian_hex2int(s[2:4])
            ret += s[4:4 + l * 2]
            s = s[4 + l * 2:]
        elif s[:2] == '4d':  # OP_PUSHDATA2
            l = little_endian_hex2int(s[2:6])
            ret += s[6:6 + l * 2]
            s = s[6 + l * 2:]
        elif s[:2] == '4e':  # OP_PUSHDATA4
            l = little_endian_hex2int(s[2:10])
            ret += s[10:10 + l * 2]
            s = s[10 + l * 2:]
        else:
            raise
    print('content: %s(%s)' % (ret, bytes.fromhex(ret).decode('utf8')))


def proc(s: str):
    """解析交易原始hex"""
    print(s)
    s = type_detector(s)
    get_bytes(s)


if __name__ == '__main__':
    import sys
    import requests
    hash = sys.argv[1]
    resp = requests.get('https://blockchain.info/rawtx/%s?format=hex' % hash)
    tx = resp.text.strip('\n\r')
    proc(hash, tx)
