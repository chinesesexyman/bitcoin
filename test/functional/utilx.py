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
    if n <= 0xfc:
        return intEncode(n, 1)
    elif n <= 0xFFFF:
        return 'fd' + intEncode(n, 2)
    elif n <= 0xFFFFFFFF:
        return 'fe' + intEncode(n, 4)
    elif n <= 0xFFFFFFFFFFFFFFFF:
        return 'ff' + intEncode(n, 8)
    return ''


def varIntDecode(data: str) -> tuple[int, int]:
    """parse data start with varInt
    data: hex data start with varInt
    return: varInt length, varInt value
    """
    if data.startswith('0x'):
        data = data[2:]
    if data[0:2] <= 'fc':
        return 1, intDecode(data[0:2])
    elif data[0:2] == 'fd':
        return 3, intDecode(data[2:6])
    elif data[0:2] == 'fe':
        return 5, intDecode(data[2:10])
    elif data[0:2] == 'ff':
        return 9, intDecode(data[2:18])
    return 0, 0
