# encoding=utf8

from test_framework.messages import CScriptWitness, CTransaction, CTxIn, CTxOut, COutPoint, CTxInWitness
from test_framework.script import CScript, taproot_construct, SegwitV0SignatureHash, hash160, LegacySignatureHash, SIGHASH_ALL
from test_framework.script import *
from test_framework.script_util import key_to_p2pkh_script
from test_framework.address import address_to_scriptpubkey, output_key_to_p2tr, key_to_p2wpkh, program_to_witness_script, keyhash_to_p2pkh_script, keyhash_to_p2pkh, bech32_to_bytes, base58_to_byte
from test_framework.key import ECKey, verify_schnorr, compute_xonly_pubkey, sign_schnorr
from bip341 import taproot_tweak_pubkey, taproot_tweak_seckey
import requests
import json
SEQUENCE = 0xffffffff
MAIN = False

secret = int(1).to_bytes(32, 'big').hex()


class CLIENT(object):
    """连接标准节点客户端"""

    def __init__(self, url, user='', password='', server_name='') -> None:
        self.url = url
        self.user = user
        self.password = password
        self.server_name = server_name

    def sendrawtransaction(self, data):
        body = {
            "jsonrpc": "1.0",
            "id": self.server_name,
            "method": "sendrawtransaction",
            "params": [data]
        }
        resp = requests.post(self.url, auth=(
            self.user, self.password), json=body)
        return json.loads(resp.content)


class CTxInX(CTxIn):
    """CTxIn子类"""

    def __init__(self, outpoint=None, scriptSig=b"", nSequence=0, nValue=0, scriptPubKey=b''):
        """增加金额属性"""
        super().__init__(outpoint, scriptSig, nSequence)
        self.nValue = nValue
        self.scriptPubKey = scriptPubKey


class TaprootKey(ECKey):
    def __init__(self, secret, compressed=True, scripts=None) -> None:
        super().__init__()
        self.set(bytes.fromhex(secret), compressed)
        self.internal_private_key = bytes.fromhex(secret)
        self.internal_public_key = compute_xonly_pubkey(
            self.internal_private_key)[0]
        self.tap = taproot_construct(self.internal_public_key, scripts=scripts)
        self.output_private_key = taproot_tweak_seckey(
            self.internal_private_key, self.tap.merkle_root)
        self.output_public_key = taproot_tweak_pubkey(
            self.internal_public_key, self.tap.merkle_root)


# 地址转换为输出脚本
def p2pkh_address_to_scriptpubkey(address):
    payload, version = base58_to_byte(address)
    if version in (0, 111):
        return keyhash_to_p2pkh_script(payload)


def segwit_address_to_scriptpubkey(address):
    version, payload = bech32_to_bytes(address)
    if version is not None:
        return program_to_witness_script(version, payload)


# 私钥转换为地址
def secret_to_key(secret, compressed=True):
    key = TaprootKey(secret, compressed=compressed)
    # key = ECKey()
    # key.set(bytes.fromhex(secret), compressed)
    return key


def secret_to_address(secret, addr_type, compressed=True, main=MAIN):
    """
    secret: hex string
    addr_type: p2pkh/p2wpkh
    compressed: True/False
    """
    key = secret_to_key(secret, compressed=compressed)
    pubkey = key.get_pubkey()
    keyhash = hash160(pubkey.get_bytes())
    if addr_type == 'p2pkh':
        return keyhash_to_p2pkh(keyhash, main=main)
    elif addr_type == 'p2wpkh':
        return key_to_p2wpkh(pubkey.get_bytes(), main=main)


def secret_to_p2tr_address(secret: str, scripts=None, main=MAIN):
    """
    private_key: hex string
    scripts: list
    """
    internal_private_key = bytes.fromhex(secret)
    internal_public_key = compute_xonly_pubkey(internal_private_key)[0]
    taproot_info = taproot_construct(internal_public_key, scripts=scripts)
    return output_key_to_p2tr(taproot_info.output_pubkey, main=main)


def make_ordi_script(content: bytes, content_type):
    ordi = [OP_FALSE, OP_IF, bytes.fromhex('6f7264'), bytes.fromhex(
        '01'), content_type.encode('utf8'), OP_0]
    start = 0
    data = content[start:start + 520]
    while len(data) != 0:
        ordi.append(data)
        start += 520
        data = content[start:start + 520]
    ordi.append(OP_ENDIF)
    return ("ordi", CScript(ordi))


key = secret_to_key(secret)
print('p2pkh addr: %s' % secret_to_address(secret, 'p2pkh', main=MAIN))
print('p2pwpkh addr: %s' % secret_to_address(secret, 'p2wpkh', main=MAIN))
print(secret_to_p2tr_address(secret))
print(address_to_scriptpubkey(secret_to_p2tr_address(secret)).hex())


# 输入
def txin_p2pkh(txid, idx, nValue, scriptPubKey=b''):
    outpoint = COutPoint(int(txid, base=16), idx)
    return CTxInX(outpoint=outpoint, nSequence=SEQUENCE, nValue=nValue, scriptPubKey=scriptPubKey)


def txin_p2wpkh(txid, idx, nValue, scriptPubKey=b''):
    outpoint = COutPoint(int(txid, base=16), idx)
    return CTxInX(outpoint=outpoint, nValue=nValue, nSequence=SEQUENCE, scriptPubKey=scriptPubKey)


def txin_p2tr(txid, idx, nValue, scriptPubKey=b''):
    outpoint = COutPoint(int(txid, base=16), idx)
    return CTxInX(outpoint=outpoint, nValue=nValue, nSequence=SEQUENCE, scriptPubKey=scriptPubKey)


# 输出
def txout_p2pkh(nValue, addr):
    return CTxOut(nValue, p2pkh_address_to_scriptpubkey(addr))


def txout_p2segwit(nValue, addr):
    return CTxOut(nValue, segwit_address_to_scriptpubkey(addr))


def transaction(vins, vouts):
    tx = CTransaction()
    tx.nVersion = 1
    tx.vin = vins
    tx.vout = vouts
    return tx


def sign_tx(tx: CTransaction, keys: list[list[str, ECKey]]):
    for idx in range(len(keys)):
        ktype, key = keys[idx]
        if ktype == 'p2pkh':
            tx.vin[idx].scriptSig = spend_p2pkh_scriptSig(key, tx, idx)
            tx.wit.vtxinwit.append(CTxInWitness())
        elif ktype == 'p2wpkh':
            script_witness = CScriptWitness()
            witness = CTxInWitness()
            script_witness.stack = spend_p2wpkh_witnessStack(
                key, tx, idx, tx.vin[idx].nValue)
            witness.scriptWitness = script_witness
            tx.wit.vtxinwit.append(witness)
        elif ktype == 'p2tr':
            script_witness = CScriptWitness()
            witness = CTxInWitness()
            script_witness.stack = spend_p2tr_witnessStack(
                key, tx, idx)
            witness.scriptWitness = script_witness
            tx.wit.vtxinwit.append(witness)
    return tx


def spend_p2pkh_scriptSig(key: ECKey, tx: CTransaction, idx: int, hash_type=SIGHASH_ALL):
    script = CScript(key_to_p2pkh_script(key.get_pubkey().get_bytes()))
    sig_hash, err = LegacySignatureHash(script, tx, idx, hash_type)
    assert err == None
    signature = key.sign_ecdsa(sig_hash)
    return CScript([signature + bytes(bytearray([hash_type])), key.get_pubkey().get_bytes()])


def spend_p2wpkh_witnessStack(key: ECKey, tx: CTransaction, idx: int, nValue: int, hash_type=SIGHASH_ALL):
    pubkey_bytes = key.get_pubkey().get_bytes()
    script = key_to_p2pkh_script(pubkey_bytes)
    sig_hash = SegwitV0SignatureHash(script, tx, idx, hash_type, nValue)
    signature = key.sign_ecdsa(sig_hash)
    return [signature + bytes(bytearray([hash_type])), pubkey_bytes]


def spend_p2tr_witnessStack(key: TaprootKey, tx: CTransaction, idx: int, hash_type=SIGHASH_DEFAULT):
    # script = CScript([key.internal_public_key, OP_CHECKSIG])
    script = CScript()
    sig_hash = TaprootSignatureHash(
        tx, tx.vin, hash_type, input_index=idx, scriptpath=False, script=script)
    signature = sign_schnorr(key.output_private_key, sig_hash)
    assert verify_schnorr(key.output_public_key[1], signature, sig_hash)
    return [signature]
    return [signature, script, bytes([LEAF_VERSION_TAPSCRIPT]) + key.internal_public_key]


if __name__ == '__main__':
    vins = [txin_p2tr(
        '2a162f08ab2095cca7a8a2b3b7766aa6307ff04e2e80d0649fa33a2d495ad107', 1, 100000000, scriptPubKey=bytes.fromhex('5120da4710964f7852695de2da025290e24af6d8c281de5a0b902b7135fd9fd74d21')),
        # txin_p2tr(
        # 'e1e8e6cea488d2c8c0083c92dcd33e9e45e5a1944797865f6ccc4623d29d9bd0', 1, 999997000, scriptPubKey=bytes.fromhex('51202d2f7b2a700ab270dd515ef7a02f25c5a344066641fcac563e1b53eca4a456d3'))
    ]
    vouts = [
        txout_p2segwit(
            99999000, 'bcrt1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5ssm803es'),
        # txout_p2segwit(
        #     999996000, 'bcrt1p95hhk2nsp2e8ph23tmm6qte9ck35gpnxg872c437rdf7ef9y2mfs3yh3x0')
    ]
    tx = transaction(vins, vouts)
    tx = sign_tx(
            tx, 
            [
                ['p2tr', key], 
                # ['p2tr', key]
            ]
        )
    raw_tx = tx.serialize_with_witness().hex()
    # print(raw_tx)
    

    # client
    client = CLIENT('http://127.0.0.1:18443', user='test', password='test')
    res = client.sendrawtransaction(raw_tx)
    print(res)
