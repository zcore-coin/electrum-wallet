import base64
import unittest
import sys
from ecdsa.util import number_to_string

from lib.bitcoin import (
    generator_secp256k1, point_to_ser, public_key_to_p2pkh, EC_KEY,
    bip32_root, bip32_public_derivation, bip32_private_derivation, pw_encode,
    pw_decode, Hash, public_key_from_private_key, address_from_private_key,
    is_address, is_private_key, xpub_from_xprv, is_new_seed, is_old_seed,
    var_int, op_push, address_to_script, regenerate_key,
    verify_message, deserialize_privkey, serialize_privkey, is_segwit_address,
    is_b58_address, address_to_scripthash, is_minikey, is_compressed, is_xpub,
    xpub_type, is_xprv, is_bip32_derivation, seed_type, EncodeBase58Check, deserialize_privkey_old, is_private_key_old)
from lib.util import bfh
from lib import constants

from . import TestCaseForTestnet


try:
    import ecdsa
except ImportError:
    sys.exit("Error: python-ecdsa does not seem to be installed. Try 'sudo pip install ecdsa'")


class Test_bitcoin(unittest.TestCase):

    def test_crypto(self):
        for message in [b"Chancellor on brink of second bailout for banks", b'\xff'*512]:
            self._do_test_crypto(message)

    def _do_test_crypto(self, message):
        G = generator_secp256k1
        _r  = G.order()
        pvk = ecdsa.util.randrange( pow(2,256) ) %_r

        Pub = pvk*G
        pubkey_c = point_to_ser(Pub,True)
        #pubkey_u = point_to_ser(Pub,False)
        addr_c = public_key_to_p2pkh(pubkey_c)

        #print "Private key            ", '%064x'%pvk
        eck = EC_KEY(number_to_string(pvk,_r))

        #print "Compressed public key  ", pubkey_c.encode('hex')
        enc = EC_KEY.encrypt_message(message, pubkey_c)
        dec = eck.decrypt_message(enc)
        self.assertEqual(message, dec)

        #print "Uncompressed public key", pubkey_u.encode('hex')
        #enc2 = EC_KEY.encrypt_message(message, pubkey_u)
        dec2 = eck.decrypt_message(enc)
        self.assertEqual(message, dec2)

        signature = eck.sign_message(message, True)
        #print signature
        EC_KEY.verify_message(eck, signature, message)

    def test_msg_signing(self):
        msg1 = b'wakiyama tamami chan'
        msg2 = b'tottemo kawaii'
        msg3 = b'yone'
        msg4 = b'watanabe thanks'

        def sign_message_with_wif_privkey(wif_privkey, msg):
            txin_type, privkey, compressed = deserialize_privkey(wif_privkey)
            key = regenerate_key(privkey)
            return key.sign_message(msg, compressed)

        def sign_message_with_wif_privkey_old(wif_privkey, msg):
            txin_type, privkey, compressed = deserialize_privkey_old(wif_privkey)
            key = regenerate_key(privkey)
            return key.sign_message(msg, compressed)

        sig1 = sign_message_with_wif_privkey(
            'T8UqLXgii9iBbQAoypL8Yz7Zta7w8QTt2qq66ViLSGXGQCGbo7rv', msg1)
        addr1 = 'MRHx4jW2KAQeEDMuK7pGLUGWvPRQT1Epmj'
        sig2 = sign_message_with_wif_privkey(
            'T3o9vVd82bASRouYDpSHo2KyFR82LB7FezpZAFDpLcbNd7AGuEJQ', msg2)
        addr2 = 'MLBCmvG4A7AqCD6MMYjf7YdV96YK5teZ5N'
        sig3 = sign_message_with_wif_privkey_old(
            'TM3TwXiEnEmKs64zCvXw2Jr9mkwgUgxNSvGyVC2nTYQMn2LcxM5C', msg3)
        addr3 = 'MEexKwbCkfepLkRPi6EfWReurzxL9eBvkU'
        sig4 = sign_message_with_wif_privkey_old(
            'TPNSUD1m5JUFLRKZ5agm5H9JVACJDEPxwS1fYjiHB6khvvbefUR5', msg4)
        addr4 = 'MNUye8sS7A5yeZVfgZD3XUwwcBgX9f27AS'

        sig1_b64 = base64.b64encode(sig1)
        sig2_b64 = base64.b64encode(sig2)
        sig3_b64 = base64.b64encode(sig3)
        sig4_b64 = base64.b64encode(sig4)

        self.assertEqual(sig1_b64, b'IDldTozCVViZ/m/gzvSf6EmZZ3ItDdM+RsI4PAxZdsb6ZQUmv3IgaJK+U4naOExaoTIVn0IY3Hoky0MWFAO6ac4=')
        self.assertEqual(sig2_b64, b'IOr6v1UPcFEoeon11dPNo+TbbLuAu8k8ccG527zmmDf/a26W6z+yAbsfTt01PKF7/UGhwJeCwybdnRXpPC2x4Hk=')
        self.assertEqual(sig3_b64, b'IIr2gW2LrTNJV4EAm6PuBXzvZBv3PbumrJNJQIf96ofxLrylCQftFeZ/Y3070dW+GcEmLXxau6/sVQb0hcGX2MY=')
        self.assertEqual(sig4_b64, b'H7WvBRrEqce85Kf56MtNZOoC3BcDR9mCqSL90Kt4swy0G4nbglT+CcKqojubEALUOJLY3ntm+hCbhD5rKzpyKCw=')

        self.assertTrue(verify_message(addr1, sig1, msg1))
        self.assertTrue(verify_message(addr2, sig2, msg2))
        self.assertTrue(verify_message(addr3, sig3, msg3))
        self.assertTrue(verify_message(addr4, sig4, msg4))

        self.assertFalse(verify_message(addr1, b'wrong', msg1))
        self.assertFalse(verify_message(addr1, sig2, msg1))
        self.assertFalse(verify_message(addr3, b'wrong', msg3))
        self.assertFalse(verify_message(addr3, sig4, msg3))

    def test_aes_homomorphic(self):
        """Make sure AES is homomorphic."""
        payload = u'\u66f4\u7a33\u5b9a\u7684\u4ea4\u6613\u5e73\u53f0'
        password = u'secret'
        enc = pw_encode(payload, password)
        dec = pw_decode(enc, password)
        self.assertEqual(dec, payload)

    def test_aes_encode_without_password(self):
        """When not passed a password, pw_encode is noop on the payload."""
        payload = u'\u66f4\u7a33\u5b9a\u7684\u4ea4\u6613\u5e73\u53f0'
        enc = pw_encode(payload, None)
        self.assertEqual(payload, enc)

    def test_aes_deencode_without_password(self):
        """When not passed a password, pw_decode is noop on the payload."""
        payload = u'\u66f4\u7a33\u5b9a\u7684\u4ea4\u6613\u5e73\u53f0'
        enc = pw_decode(payload, None)
        self.assertEqual(payload, enc)

    def test_aes_decode_with_invalid_password(self):
        """pw_decode raises an Exception when supplied an invalid password."""
        payload = u"blah"
        password = u"uber secret"
        wrong_password = u"not the password"
        enc = pw_encode(payload, password)
        self.assertRaises(Exception, pw_decode, enc, wrong_password)

    def test_hash(self):
        """Make sure the Hash function does sha256 twice"""
        payload = u"test"
        expected = b'\x95MZI\xfdp\xd9\xb8\xbc\xdb5\xd2R&x)\x95\x7f~\xf7\xfalt\xf8\x84\x19\xbd\xc5\xe8"\t\xf4'

        result = Hash(payload)
        self.assertEqual(expected, result)

    def test_var_int(self):
        for i in range(0xfd):
            self.assertEqual(var_int(i), "{:02x}".format(i) )

        self.assertEqual(var_int(0xfd), "fdfd00")
        self.assertEqual(var_int(0xfe), "fdfe00")
        self.assertEqual(var_int(0xff), "fdff00")
        self.assertEqual(var_int(0x1234), "fd3412")
        self.assertEqual(var_int(0xffff), "fdffff")
        self.assertEqual(var_int(0x10000), "fe00000100")
        self.assertEqual(var_int(0x12345678), "fe78563412")
        self.assertEqual(var_int(0xffffffff), "feffffffff")
        self.assertEqual(var_int(0x100000000), "ff0000000001000000")
        self.assertEqual(var_int(0x0123456789abcdef), "ffefcdab8967452301")

    def test_op_push(self):
        self.assertEqual(op_push(0x00), '00')
        self.assertEqual(op_push(0x12), '12')
        self.assertEqual(op_push(0x4b), '4b')
        self.assertEqual(op_push(0x4c), '4c4c')
        self.assertEqual(op_push(0xfe), '4cfe')
        self.assertEqual(op_push(0xff), '4cff')
        self.assertEqual(op_push(0x100), '4d0001')
        self.assertEqual(op_push(0x1234), '4d3412')
        self.assertEqual(op_push(0xfffe), '4dfeff')
        self.assertEqual(op_push(0xffff), '4dffff')
        self.assertEqual(op_push(0x10000), '4e00000100')
        self.assertEqual(op_push(0x12345678), '4e78563412')

    def test_address_to_script(self):
        # bech32 native segwit
        # test vectors from BIP-0173 TODO
        self.assertEqual(address_to_script('MONA1Q4KPN6PSTHGD5UR894AUHJJ2G02WLGMP8KE08NE'), '0014ad833d060bba1b4e0ce5af797949487a9df46c27')
        self.assertEqual(address_to_script('mona1qp8f842ywwr9h5rdxyzggex7q3trvvvaarfssxccju52rj6htfzfsqr79j2'), '002009d27aa88e70cb7a0da620908c9bc08ac6c633bd1a61036312e514396aeb4893')
        self.assertEqual(address_to_script('mona1sw50qpvnxy8'), '6002751e')
        self.assertEqual(address_to_script('mona1zw508d6qejxtdg4y5r3zarvaryvhm3vz7'), '5210751e76e8199196d454941c45d1b3a323')

        # base58 P2PKH
        self.assertEqual(address_to_script('MFMy9FwJsV6HiN5eZDqDETw4pw52q3UGrb'), '76a91451dadacc7021440cbe4ca148a5db563b329b4c0388ac')
        self.assertEqual(address_to_script('MVELZC3ks1Xk59kvKWuSN3mpByNwaxeaBJ'), '76a914e9fb298e72e29ebc2b89864a5e4ae10e0b84726088ac')

        # base58 P2SH
        self.assertEqual(address_to_script('PHjTKtgYLTJ9D2Bzw2f6xBB41KBm2HeGfg'), 'a9146449f568c9cd2378138f2636e1567112a184a9e887')
        self.assertEqual(address_to_script('3AqJ6Tn8qS8LKMDfi41AhuZiY6JbR6mt6E'), 'a9146449f568c9cd2378138f2636e1567112a184a9e887')


class Test_bitcoin_testnet(TestCaseForTestnet):

    def test_address_to_script(self):
        # bech32 native segwit
        # test vectors from BIP-0173
        self.assertEqual(address_to_script('tmona1qfj8lu0rafk2mpvk7jj62q8eerjpex3xlcadtupkrkhh5a73htmhs68e55m'), '00204c8ffe3c7d4d95b0b2de94b4a01f391c839344dfc75abe06c3b5ef4efa375eef')
        self.assertEqual(address_to_script('tmona1q0p29rfu7ap3duzqj5t9e0jzgqzwdtd97pa5rhuz4r38t5a6dknyqxmyyaz'), '0020785451a79ee862de0812a2cb97c848009cd5b4be0f683bf0551c4eba774db4c8')

        # base58 P2PKH
        self.assertEqual(address_to_script('mptvgSbAs4iwxQ7JQZdEN6Urpt3dtjbawd'), '76a91466e0ef980c8ff8129e8d0f716b2ce1df2f97bbbf88ac')
        self.assertEqual(address_to_script('mrodaP7iH3B9ZXSptfGQXLKE3hfdjMdf7y'), '76a9147bd0d45ec256701811ebb38cfd2ba3d17576bf3e88ac')

        # base58 P2SH
        self.assertEqual(address_to_script('pJwLxfRRUhAaYJsKzKCk9cATAn8Do2SS7L'), 'a91492e825fa92f4aa873c6caf4b20f6c7e949b456a987')
        self.assertEqual(address_to_script('pHNnBm6ECsh5QsUyXMzdoAXV8qV68wj2M4'), 'a91481c75a711f23443b44d70b10ddf856e39a6b254d87')


class Test_xprv_xpub(unittest.TestCase):

    xprv_xpub = (
        # Taken from test vectors in https://en.bitcoin.it/wiki/BIP_0032_TestVectors
        {'xprv': 'xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76',
         'xpub': 'xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy',
         'xtype': 'standard'},
        {'xprv': 'yprvAJEYHeNEPcyBoQYM7sGCxDiNCTX65u4ANgZuSGTrKN5YCC9MP84SBayrgaMyZV7zvkHrr3HVPTK853s2SPk4EttPazBZBmz6QfDkXeE8Zr7',
         'xpub': 'ypub6XDth9u8DzXV1tcpDtoDKMf6kVMaVMn1juVWEesTshcX4zUVvfNgjPJLXrD9N7AdTLnbHFL64KmBn3SNaTe69iZYbYCqLCCNPZKbLz9niQ4',
         'xtype': 'p2wpkh-p2sh'},
        {'xprv': 'zprvAWgYBBk7JR8GkraNZJeEodAp2UR1VRWJTXyV1ywuUVs1awUgTiBS1ZTDtLA5F3MFDn1LZzu8dUpSKdT7ToDpvEG6PQu4bJs7zQY47Sd3sEZ',
         'xpub': 'zpub6jftahH18ngZyLeqfLBFAm7YaWFVttE9pku5pNMX2qPzTjoq1FVgZMmhjecyB2nqFb31gHE9vNvbaggU6vvWpNZbXEWLLUjYjFqG95LNyT8',
         'xtype': 'p2wpkh'},
    )

    def _do_test_bip32(self, seed, sequence):
        xprv, xpub = bip32_root(bfh(seed), 'standard')
        self.assertEqual("m/", sequence[0:2])
        path = 'm'
        sequence = sequence[2:]
        for n in sequence.split('/'):
            child_path = path + '/' + n
            if n[-1] != "'":
                xpub2 = bip32_public_derivation(xpub, path, child_path)
            xprv, xpub = bip32_private_derivation(xprv, path, child_path)
            if n[-1] != "'":
                self.assertEqual(xpub, xpub2)
            path = child_path

        return xpub, xprv

    def test_bip32(self):
        # see https://en.bitcoin.it/wiki/BIP_0032_TestVectors
        xpub, xprv = self._do_test_bip32("000102030405060708090a0b0c0d0e0f", "m/0'/1/2'/2/1000000000")
        self.assertEqual("xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy", xpub)
        self.assertEqual("xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76", xprv)

        xpub, xprv = self._do_test_bip32("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542","m/0/2147483647'/1/2147483646'/2")
        self.assertEqual("xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt", xpub)
        self.assertEqual("xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j", xprv)

    def test_xpub_from_xprv(self):
        """We can derive the xpub key from a xprv."""
        for xprv_details in self.xprv_xpub:
            result = xpub_from_xprv(xprv_details['xprv'])
            self.assertEqual(result, xprv_details['xpub'])

    def test_is_xpub(self):
        for xprv_details in self.xprv_xpub:
            xpub = xprv_details['xpub']
            self.assertTrue(is_xpub(xpub))
        self.assertFalse(is_xpub('xpub1nval1d'))
        self.assertFalse(is_xpub('xpub661MyMwAqRbcFWohJWt7PHsFEJfZAvw9ZxwQoDa4SoMgsDDM1T7WK3u9E4edkC4ugRnZ8E4xDZRpk8Rnts3Nbt97dPwT52WRONGBADWRONG'))

    def test_xpub_type(self):
        for xprv_details in self.xprv_xpub:
            xpub = xprv_details['xpub']
            self.assertEqual(xprv_details['xtype'], xpub_type(xpub))

    def test_is_xprv(self):
        for xprv_details in self.xprv_xpub:
            xprv = xprv_details['xprv']
            self.assertTrue(is_xprv(xprv))
        self.assertFalse(is_xprv('xprv1nval1d'))
        self.assertFalse(is_xprv('xprv661MyMwAqRbcFWohJWt7PHsFEJfZAvw9ZxwQoDa4SoMgsDDM1T7WK3u9E4edkC4ugRnZ8E4xDZRpk8Rnts3Nbt97dPwT52WRONGBADWRONG'))

    def test_is_bip32_derivation(self):
        self.assertTrue(is_bip32_derivation("m/0'/1"))
        self.assertTrue(is_bip32_derivation("m/0'/0'"))
        self.assertTrue(is_bip32_derivation("m/44'/22'/0'/0/0"))
        self.assertTrue(is_bip32_derivation("m/49'/22'/0'/0/0"))
        self.assertFalse(is_bip32_derivation("mmmmmm"))
        self.assertFalse(is_bip32_derivation("n/"))
        self.assertFalse(is_bip32_derivation(""))
        self.assertFalse(is_bip32_derivation("m/q8462"))

    def test_version_bytes(self):
        xprv_headers_b58 = {
            'standard':    'xprv',
            'p2wpkh-p2sh': 'yprv',
            'p2wsh-p2sh':  'Yprv',
            'p2wpkh':      'zprv',
            'p2wsh':       'Zprv',
        }
        xpub_headers_b58 = {
            'standard':    'xpub',
            'p2wpkh-p2sh': 'ypub',
            'p2wsh-p2sh':  'Ypub',
            'p2wpkh':      'zpub',
            'p2wsh':       'Zpub',
        }
        for xtype, xkey_header_bytes in constants.net.XPRV_HEADERS.items():
            xkey_header_bytes = bfh("%08x" % xkey_header_bytes)
            xkey_bytes = xkey_header_bytes + bytes([0] * 74)
            xkey_b58 = EncodeBase58Check(xkey_bytes)
            self.assertTrue(xkey_b58.startswith(xprv_headers_b58[xtype]))

            xkey_bytes = xkey_header_bytes + bytes([255] * 74)
            xkey_b58 = EncodeBase58Check(xkey_bytes)
            self.assertTrue(xkey_b58.startswith(xprv_headers_b58[xtype]))

        for xtype, xkey_header_bytes in constants.net.XPUB_HEADERS.items():
            xkey_header_bytes = bfh("%08x" % xkey_header_bytes)
            xkey_bytes = xkey_header_bytes + bytes([0] * 74)
            xkey_b58 = EncodeBase58Check(xkey_bytes)
            self.assertTrue(xkey_b58.startswith(xpub_headers_b58[xtype]))

            xkey_bytes = xkey_header_bytes + bytes([255] * 74)
            xkey_b58 = EncodeBase58Check(xkey_bytes)
            self.assertTrue(xkey_b58.startswith(xpub_headers_b58[xtype]))


class Test_xprv_xpub_testnet(TestCaseForTestnet):

    def test_version_bytes(self):
        xprv_headers_b58 = {
            'standard':    'tprv',
            'p2wpkh-p2sh': 'uprv',
            'p2wsh-p2sh':  'Uprv',
            'p2wpkh':      'vprv',
            'p2wsh':       'Vprv',
        }
        xpub_headers_b58 = {
            'standard':    'tpub',
            'p2wpkh-p2sh': 'upub',
            'p2wsh-p2sh':  'Upub',
            'p2wpkh':      'vpub',
            'p2wsh':       'Vpub',
        }
        for xtype, xkey_header_bytes in constants.net.XPRV_HEADERS.items():
            xkey_header_bytes = bfh("%08x" % xkey_header_bytes)
            xkey_bytes = xkey_header_bytes + bytes([0] * 74)
            xkey_b58 = EncodeBase58Check(xkey_bytes)
            self.assertTrue(xkey_b58.startswith(xprv_headers_b58[xtype]))

            xkey_bytes = xkey_header_bytes + bytes([255] * 74)
            xkey_b58 = EncodeBase58Check(xkey_bytes)
            self.assertTrue(xkey_b58.startswith(xprv_headers_b58[xtype]))

        for xtype, xkey_header_bytes in constants.net.XPUB_HEADERS.items():
            xkey_header_bytes = bfh("%08x" % xkey_header_bytes)
            xkey_bytes = xkey_header_bytes + bytes([0] * 74)
            xkey_b58 = EncodeBase58Check(xkey_bytes)
            self.assertTrue(xkey_b58.startswith(xpub_headers_b58[xtype]))

            xkey_bytes = xkey_header_bytes + bytes([255] * 74)
            xkey_b58 = EncodeBase58Check(xkey_bytes)
            self.assertTrue(xkey_b58.startswith(xpub_headers_b58[xtype]))


class Test_keyImport(unittest.TestCase):

    priv_pub_addr = (
           {'priv': 'T9ZV9h1ZkYfgh2E2h5CZbEzrc32nz3uK2KjhA1Amu7JzNo99YGxg',
            'exported_privkey': 'p2pkh:T9ZV9h1ZkYfgh2E2h5CZbEzrc32nz3uK2KjhA1Amu7JzNo99YGxg',
            'pub': '0251ce5368b2ac47b6e7fb7222c1180ea0012e4891b56cefb8d9d187bc7ad11659',
            'address': 'MN3qk8taHHcLp52tf6v9V4CyfiJuCpwz4B',
            'minikey' : False,
            'txin_type': 'p2pkh',
            'compressed': True,
            'addr_encoding': 'base58',
            'scripthash': '33c5367b611c9183b2eedf0a32de2fa57f399f75e6b884fdaaf95a655f706d7c'},
           {'priv': 'p2pkh:T4kGgvhsaiWqfcfQi9KMbpV3KUWo4cNhVm4fwNqi4PNH94NFBePL',
            'exported_privkey': 'p2pkh:T4kGgvhsaiWqfcfQi9KMbpV3KUWo4cNhVm4fwNqi4PNH94NFBePL',
            'pub': '031fc22d17f7f4353a1041c67ba02e58a218d3f7519236db1a583e9f5ff87fc87a',
            'address': 'MWFdhfqsJrE9jeu6WYrgf8SyAaHcTaq9mo',
            'minikey': False,
            'txin_type': 'p2pkh',
            'compressed': True,
            'addr_encoding': 'base58',
            'scripthash': '3bd7fabf96d797e2f6d933a0ade1b3bf0b1a60bdb82bcd10ec3a9d4d01bdeb19'},
           {'priv': '6ymMe23cQJpFbeURHAk55m6iQDP2BNNFwmempMtpGxKj9idvR8K',
            'exported_privkey': 'p2wpkh-p2sh:6ussHZ9YhTToL1K1U1W5B7uAZz9asxgWNVWZL4X2HeJxAZ31tGq',
            'pub': '041958d7b0db55e8c42912231ade8713aa1127603c78ce91fa3be5a8386d24b4a03efe44e3c5f56362a268f84a8a42f75a50fbb6f976198dae2cea926df1439f87',
            'address': 'PT7Y9pqWHZHfsnk1dw9ejq3Yp2pQ6qBSCf',
            'minikey': False,
            'txin_type': 'p2wpkh-p2sh',
            'compressed': False,
            'addr_encoding': 'base58',
            'scripthash': '8a11cc149d7dce867caccf61e5481d00acf782f790b169bf808b4a6ab32a5efb'},
           {'priv': 'p2wpkh-p2sh:6ussHZ9YhTToL1K1U1W5B7uAZz9asxgWNVWZL4X2HeJxAZ31tGq',
            'exported_privkey': 'p2wpkh-p2sh:6ussHZ9YhTToL1K1U1W5B7uAZz9asxgWNVWZL4X2HeJxAZ31tGq',
            'pub': '041958d7b0db55e8c42912231ade8713aa1127603c78ce91fa3be5a8386d24b4a03efe44e3c5f56362a268f84a8a42f75a50fbb6f976198dae2cea926df1439f87',
            'address': 'PT7Y9pqWHZHfsnk1dw9ejq3Yp2pQ6qBSCf',
            'minikey': False,
            'txin_type': 'p2wpkh-p2sh',
            'compressed': False,
            'addr_encoding': 'base58',
            'scripthash': '8a11cc149d7dce867caccf61e5481d00acf782f790b169bf808b4a6ab32a5efb'},
           {'priv': 'TNAttqWnTUoRfgduAasFX7oZNj3oC28euS3nQCmt5rfy6Uk5FBEr',
            'exported_privkey': 'p2wpkh-p2sh:T51dkWnz7Ay9iecN4S5TvmcasreVXBbCaYoXHJ5h6uAYXpM8MGDS',
            'pub': '0273a3c1bd660286dc632400f8ecaaf9d782b8941e0cc5e1bc73308e658510021c',
            'address': 'PN7E5z6oUHf6aQQivCmmn8haFe6FtYshAJ',
            'minikey': False,
            'txin_type': 'p2wpkh-p2sh',
            'compressed': True,
            'addr_encoding': 'base58',
            'scripthash': '8945b92543e13adc7c3d35d2be7924c00a125a25741f15fe5df8275a7c15cd42'},
           {'priv': 'p2wpkh-p2sh:T51dkWnz7Ay9iecN4S5TvmcasreVXBbCaYoXHJ5h6uAYXpM8MGDS',
            'exported_privkey': 'p2wpkh-p2sh:T51dkWnz7Ay9iecN4S5TvmcasreVXBbCaYoXHJ5h6uAYXpM8MGDS',
            'pub': '0273a3c1bd660286dc632400f8ecaaf9d782b8941e0cc5e1bc73308e658510021c',
            'address': 'PN7E5z6oUHf6aQQivCmmn8haFe6FtYshAJ',
            'minikey': False,
            'txin_type': 'p2wpkh-p2sh',
            'compressed': True,
            'addr_encoding': 'base58',
            'scripthash': '8945b92543e13adc7c3d35d2be7924c00a125a25741f15fe5df8275a7c15cd42'},
           {'priv': 'TH9hBPJWPL7n63oN2QkQFRLWYsFDUKd7sqjuauvmU3H5KxKR4vZG',
            'exported_privkey': 'p2wpkh:T8a4cDwcDBCe7XnbULMWTFF2JS3ZduMPiQ7n2TafyZXN3dAqzEg5',
            'pub': '03b9ace321eddd5037f35bc141a9f6cbd54d5064b917da1ef02e1b575f410f5e11',
            'address': 'mona1quunc907zfyj7cyxhnp9584rj0wmdka2ec9w3af',
            'minikey': False,
            'txin_type': 'p2wpkh',
            'compressed': True,
            'addr_encoding': 'bech32',
            'scripthash': 'bdd0b86d7c9290b25b8528f01739358445cd9d050e8aef8099eb74f8e34db082'},
           {'priv': 'p2wpkh:T8a4cDwcDBCe7XnbULMWTFF2JS3ZduMPiQ7n2TafyZXN3dAqzEg5',
            'exported_privkey': 'p2wpkh:T8a4cDwcDBCe7XnbULMWTFF2JS3ZduMPiQ7n2TafyZXN3dAqzEg5',
            'pub': '03b9ace321eddd5037f35bc141a9f6cbd54d5064b917da1ef02e1b575f410f5e11',
            'address': 'mona1quunc907zfyj7cyxhnp9584rj0wmdka2ec9w3af',
            'minikey': False,
            'txin_type': 'p2wpkh',
            'compressed': True,
            'addr_encoding': 'bech32',
            'scripthash': 'bdd0b86d7c9290b25b8528f01739358445cd9d050e8aef8099eb74f8e34db082'},
           # from http://bitscan.com/articles/security/spotlight-on-mini-private-keys
           {'priv': 'SzavMBLoXU6kDrqtUVmffv',
            'exported_privkey': 'p2pkh:TAsve34b6yMQn1hBGTc472BfW8kvEoct5MhZrxADHEB7oZgBbky4',
            'pub': '02588d202afcc1ee4ab5254c7847ec25b9a135bbda0f2bc69ee1a714749fd77dc9',
            'address': 'MGB59epkrViwpW6QARm5vCQGAaWErLrsUx',
            'minikey': True,
            'txin_type': 'p2pkh',
            'compressed': True,  # this is actually ambiguous... issue #2748
            'addr_encoding': 'base58',
            'scripthash': '60ad5a8b922f758cd7884403e90ee7e6f093f8d21a0ff24c9a865e695ccefdf1'},
    )

    priv_pub_addr_old = (
           {'priv': 'TNsb2t6wGVTrZCeeTP5C9eEA3UdqQpDCaYQYbEof1wPuTDzLsbni',
            'exported_privkey': 'p2pkh:TNsb2t6wGVTrZCeeTP5C9eEA3UdqQpDCaYQYbEof1wPuTDzLsbni',
            'pub': '03581803a5795674e8ba65765d7d8bc4c89ce96835e19538437390b010a0e693f7',
            'address': 'MKLkoVY9am6aRxTeCAzVrywyg8PC5uQVPW',
            'minikey' : False,
            'txin_type': 'p2pkh',
            'compressed': True,
            'addr_encoding': 'base58'},
           {'priv': 'TNsb2t6wGVTrZCeeTP5C9eEA3UdqQpDCaYQYbEof1wPuTDzLsbni',
            'exported_privkey': 'TNsb2t6wGVTrZCeeTP5C9eEA3UdqQpDCaYQYbEof1wPuTDzLsbni',
            'pub': '03581803a5795674e8ba65765d7d8bc4c89ce96835e19538437390b010a0e693f7',
            'address': 'MKLkoVY9am6aRxTeCAzVrywyg8PC5uQVPW',
            'minikey' : False,
            'txin_type': 'p2pkh',
            'compressed': True,
            'addr_encoding': 'base58'}
    )

    def test_public_key_from_private_key(self):
        for priv_details in self.priv_pub_addr:
            txin_type, privkey, compressed = deserialize_privkey(priv_details['priv'])
            result = public_key_from_private_key(privkey, compressed)
            self.assertEqual(priv_details['pub'], result)
            self.assertEqual(priv_details['txin_type'], txin_type)
            self.assertEqual(priv_details['compressed'], compressed)

    def test_address_from_private_key(self):
        for priv_details in self.priv_pub_addr:
            addr2 = address_from_private_key(priv_details['priv'])
            self.assertEqual(priv_details['address'], addr2)

    def test_is_valid_address(self):
        for priv_details in self.priv_pub_addr:
            addr = priv_details['address']
            self.assertFalse(is_address(priv_details['priv']))
            self.assertFalse(is_address(priv_details['pub']))
            self.assertTrue(is_address(addr))

            is_enc_b58 = priv_details['addr_encoding'] == 'base58'
            self.assertEqual(is_enc_b58, is_b58_address(addr))

            is_enc_bech32 = priv_details['addr_encoding'] == 'bech32'
            self.assertEqual(is_enc_bech32, is_segwit_address(addr))

        self.assertFalse(is_address("not an address"))

    def test_is_private_key(self):
        for priv_details in self.priv_pub_addr:
            self.assertTrue(is_private_key(priv_details['priv']))
            self.assertTrue(is_private_key(priv_details['exported_privkey']))
            self.assertFalse(is_private_key(priv_details['pub']))
            self.assertFalse(is_private_key(priv_details['address']))
        self.assertFalse(is_private_key("not a privkey"))

    def test_is_private_key_old(self):
        for priv_details in self.priv_pub_addr_old:
            self.assertTrue(is_private_key_old(priv_details['priv']))
            self.assertTrue(is_private_key_old(priv_details['exported_privkey']))
            self.assertFalse(is_private_key_old(priv_details['pub']))
            self.assertFalse(is_private_key_old(priv_details['address']))
        self.assertFalse(is_private_key_old("not a privkey"))

    def test_serialize_privkey(self):
        for priv_details in self.priv_pub_addr:
            txin_type, privkey, compressed = deserialize_privkey(priv_details['priv'])
            priv2 = serialize_privkey(privkey, compressed, txin_type)
            self.assertEqual(priv_details['exported_privkey'], priv2)

    def test_address_to_scripthash(self):
        for priv_details in self.priv_pub_addr:
            sh = address_to_scripthash(priv_details['address'])
            self.assertEqual(priv_details['scripthash'], sh)

    def test_is_minikey(self):
        for priv_details in self.priv_pub_addr:
            minikey = priv_details['minikey']
            priv = priv_details['priv']
            self.assertEqual(minikey, is_minikey(priv))

    def test_is_compressed(self):
        for priv_details in self.priv_pub_addr:
            self.assertEqual(priv_details['compressed'],
                             is_compressed(priv_details['priv']))


class Test_seeds(unittest.TestCase):
    """ Test old and new seeds. """

    mnemonics = {
        ('cell dumb heartbeat north boom tease ship baby bright kingdom rare squeeze', 'old'),
        ('cell dumb heartbeat north boom tease ' * 4, 'old'),
        ('cell dumb heartbeat north boom tease ship baby bright kingdom rare badword', ''),
        ('cElL DuMb hEaRtBeAt nOrTh bOoM TeAsE ShIp bAbY BrIgHt kInGdOm rArE SqUeEzE', 'old'),
        ('   cElL  DuMb hEaRtBeAt nOrTh bOoM  TeAsE ShIp    bAbY BrIgHt kInGdOm rArE SqUeEzE   ', 'old'),
        # below seed is actually 'invalid old' as it maps to 33 hex chars
        ('hurry idiot prefer sunset mention mist jaw inhale impossible kingdom rare squeeze', 'old'),
        ('cram swing cover prefer miss modify ritual silly deliver chunk behind inform able', 'standard'),
        ('cram swing cover prefer miss modify ritual silly deliver chunk behind inform', ''),
        ('ostrich security deer aunt climb inner alpha arm mutual marble solid task', 'standard'),
        ('OSTRICH SECURITY DEER AUNT CLIMB INNER ALPHA ARM MUTUAL MARBLE SOLID TASK', 'standard'),
        ('   oStRiCh sEcUrItY DeEr aUnT ClImB       InNeR AlPhA ArM MuTuAl mArBlE   SoLiD TaSk  ', 'standard'),
        ('x8', 'standard'),
        ('science dawn member doll dutch real can brick knife deny drive list', '2fa'),
        ('science dawn member doll dutch real ca brick knife deny drive list', ''),
        (' sCience dawn   member doll Dutch rEAl can brick knife deny drive  lisT', '2fa'),
        ('frost pig brisk excite novel report camera enlist axis nation novel desert', 'segwit'),
        ('  fRoSt pig brisk excIte novel rePort CamEra enlist axis nation nOVeL dEsert ', 'segwit'),
        ('9dk', 'segwit'),
    }
    
    def test_new_seed(self):
        seed = "cram swing cover prefer miss modify ritual silly deliver chunk behind inform able"
        self.assertTrue(is_new_seed(seed))

        seed = "cram swing cover prefer miss modify ritual silly deliver chunk behind inform"
        self.assertFalse(is_new_seed(seed))

    def test_old_seed(self):
        self.assertTrue(is_old_seed(" ".join(["like"] * 12)))
        self.assertFalse(is_old_seed(" ".join(["like"] * 18)))
        self.assertTrue(is_old_seed(" ".join(["like"] * 24)))
        self.assertFalse(is_old_seed("not a seed"))

        self.assertTrue(is_old_seed("0123456789ABCDEF" * 2))
        self.assertTrue(is_old_seed("0123456789ABCDEF" * 4))

    def test_seed_type(self):
        for seed_words, _type in self.mnemonics:
            self.assertEqual(_type, seed_type(seed_words), msg=seed_words)
