"""ZCore masternode support."""
import time
import base64

from . import bitcoin
from . import ecc
from .bitcoin import hash_encode, hash_decode, deserialize_privkey
from .transaction import BCDataStream, parse_input, parse_outpoint
from . import util
from .util import bfh, bh2u, to_bytes, to_string
import ipaddress
import socket


class NetworkAddress(object):
    DEFAULT_PORT = 17293

    """A network address."""

    def __init__(self, address='',port=None):
        self.ip = ''
        self.port = self.DEFAULT_PORT
        self.type = 4  # defaults to IPv4

        if len(address) == 0:
            return

        # IPv4/IPv6
        # 127.0.0.1
        # 127.0.0.1:9333
        # ::1
        if address.find('[', 0, 2) == -1:
            # 127.0.0.1:80
            if address.find('::') == -1 and address.find(':') > -1:
                self.ip = address.split(':')[0]
                self.port = int(address.split(':')[1])
            else:
                if address.find('::') > -1:
                    self.type = 6
                self.ip = address
        else:
            # IPv6
            # [::1]:9333
            self.type = 6

            ip6, port = address.rsplit(':', 1)
            self.ip = ip6.strip('[]')
            self.port = int(port)

        try:
            ipaddress.ip_address(self.ip)
        except ValueError:
            raise Exception('invalid address')

    @classmethod
    def from_dict(self, d):
        kwargs = {}
        for key in ['ip', 'port']:
            kwargs[key] = d.get(key)

        # IPv6
        if kwargs['ip'].find('::') > -1:
            return self('['+kwargs['ip']+']:'+str(kwargs['port']))

        return self(kwargs['ip']+':'+str(kwargs['port']))

    def __str__(self):
        if self.type == 4:
            return '%s:%s' % (self.ip, self.port)
        else:
            return '[%s]:%s' % (self.ip, self.port)

    @classmethod
    def deserialize(cls, vds):
        # IPv4-mapped IPv6 address.
        _ = vds.read_bytes(12)
        ip = []
        for i in range(4):
            ip.append(vds._read_num('<B'))
        ip = '.'.join(map(str, ip))
        # Ports are encoded as big-endian.
        port = vds._read_num('>H')
        return cls(ip+':'+str(port))

    def serialize(self, vds=None):
        if not vds:
            vds = BCDataStream()
        # IPv4-mapped IPv6 address.
        vds.write(bfh('00000000000000000000ffff'))

        ip = map(int, self.ip.split('.'))
        for i in ip:
            vds._write_num('<B', i)
        # Ports are encoded as big-endian.
        vds._write_num('>H', self.port)
        return bh2u(vds.input)

    def dump(self):
        return {'ip': self.ip, 'port': self.port}


class MasternodePing(object):
    """A masternode ping message."""

    @classmethod
    def from_dict(cls, d, protocol_version):
        kwargs = {}
        for key in ['vin', 'block_hash', 'sig_time', 'sig']:
            kwargs[key] = d.get(key)

        if kwargs.get('vin'):
            kwargs['vin'] = kwargs['vin']
        else:
            kwargs['vin'] = {}

        if kwargs.get('sig'):
            kwargs['sig'] = base64.b64decode(kwargs['sig'])
        else:
            kwargs['sig'] = ''

        kwargs['protocol_version'] = protocol_version

        return cls(**kwargs)

    def __init__(self, vin=None, block_hash='', sig_time=0, sig='',
                 protocol_version=70922):
        if vin is None:
            vin = {'prevout_hash': '', 'prevout_n': 0,
                   'scriptSig': '', 'sequence': 0xffffffff}
        else:
            vin.update({'scriptSig': '', 'sequence': 0xffffffff})
        self.vin = vin
        self.block_hash = block_hash
        self.sig_time = int(sig_time)
        self.sig = sig
        self.protocol_version = int(protocol_version)

    @classmethod
    def deserialize(cls, vds, protocol_version=70922):
        vin = parse_input(vds, full_parse=True)
        block_hash = hash_encode(vds.read_bytes(32))

        sig_time = vds.read_int64()
        sig = vds.read_bytes(vds.read_compact_size())
        return cls(vin=vin, block_hash=block_hash, sig_time=sig_time,
                   sig=sig, protocol_version=protocol_version)

    def serialize(self, vds=None):
        if not vds:
            vds = BCDataStream()
        serialize_input(vds, self.vin)
        vds.write(hash_decode(self.block_hash))
        vds.write_int64(self.sig_time)
        vds.write_string(self.sig)
        return bh2u(vds.input)

    def serialize_for_sig(self, update_time=False):
        s = serialize_input_str(self.vin)
        s += self.block_hash

        if update_time:
            self.sig_time = int(time.time())
        s += str(self.sig_time)
        return to_bytes(s)

    def sign(self, wif, current_time=None):
        """Sign this ping.

        If current_time is specified, sig_time will not be updated.
        """
        update_time = True
        if current_time is not None:
            self.sig_time = current_time
            update_time = False

        txin_type, key, is_compressed = bitcoin.deserialize_privkey(
            'p2pkh:'+wif)
        eckey = ecc.ECPrivkey(key)
        serialized = self.serialize_for_sig(update_time=update_time)

        self.sig = eckey.sign_message(serialized, is_compressed)
        return self.sig

    def dump(self):
        sig = base64.b64encode(to_bytes(self.sig)).decode('utf-8')
        return {'vin': self.vin, 'block_hash': self.block_hash, 'sig_time': self.sig_time, 'sig': sig}


def serialize_outpoint(vds, outpoint):
    vds.write(hash_decode(outpoint['prevout_hash']))
    vds.write_uint32(outpoint['prevout_n'])


def serialize_input(vds, vin):
    vds.write(hash_decode(vin['prevout_hash']))
    vds.write_uint32(vin['prevout_n'])
    vds.write_string(vin['scriptSig'])
    vds.write_uint32(vin['sequence'])


def serialize_input_str(vin):
    """Used by MasternodePing in its serialization for signing."""
    s = ['CTxIn(']
    s.append('COutPoint(%s, %s)' % (vin['prevout_hash'], vin['prevout_n']))
    s.append(', ')
    if vin['prevout_hash'] == '00'*32 and vin['prevout_n'] == 0xffffffff:
        s.append('coinbase %s' % vin['scriptSig'])
    else:
        scriptSig = vin['scriptSig']
        if len(scriptSig) > 24:
            scriptSig = scriptSig[0:24]
        s.append('scriptSig=%s' % scriptSig)

    if vin['sequence'] != 0xffffffff:
        s.append(', nSequence=%d' % vin['sequence'])
    s.append(')')
    return ''.join(s)


class MasternodeAnnounce(object):
    """A masternode announce message.

    Attributes:
        - alias: Alias to help the user identify this masternode.
        - vin: 2500 MUE input.
        - addr: Address that the masternode can be reached at.
        - collateral_key: Key that can spend the 2500 MUE input.
        - private_key: Key that the masternode will sign pings with.
        - masternode_pubkey: Key that will sign the message with.
        - sig: Message signature.
        - sig_time: Message signature creation time.
        - protocol_version: The masternode's protocol version.
        - last_ping: The last time the masternode pinged the network.
        - announced: Whether this announce has been broadcast.

    """

    def __init__(self, alias='', vin=None, addr=NetworkAddress(),
                 collateral_key='', masternode_pubkey='', sig='', sig_time=0,
                 protocol_version=70922, last_ping=MasternodePing(),
                 announced=False):
        self.alias = alias
        if vin is None:
            vin = {'prevout_hash': '', 'prevout_n': 0,
                   'scriptSig': '', 'sequence': 0xffffffff}
        else:
            vin.update({'scriptSig': '', 'sequence': 0xffffffff})
        self.vin = vin
        self.addr = addr
        self.collateral_key = collateral_key
        self.masternode_pubkey = masternode_pubkey
        self.sig = sig
        self.sig_time = int(sig_time)
        self.protocol_version = int(protocol_version)
        self.last_ping = last_ping
        self.announced = announced

    @classmethod
    def deserialize(cls, raw):
        vds = BCDataStream()
        vds.write(bfh(raw))

        version = vds.read_bytes(1)
        vin = parse_input(vds, full_parse=True)
        address = NetworkAddress.deserialize(vds)
        collateral_pubkey = bh2u(vds.read_bytes(vds.read_compact_size()))
        masternode_pubkey = bh2u(vds.read_bytes(vds.read_compact_size()))
        sig = vds.read_bytes(vds.read_compact_size())

        sig_time = vds.read_int64()

        protocol_version = vds.read_uint32()

        last_ping = MasternodePing.deserialize(vds, protocol_version)

        kwargs = {'vin': vin, 'addr': address,
                  'collateral_key': collateral_pubkey,
                  'masternode_pubkey': masternode_pubkey,
                  'sig': sig, 'sig_time': sig_time,
                  'protocol_version': protocol_version, 'last_ping': last_ping}
        return cls(**kwargs)

    def serialize(self, vds=None):
        if not vds:
            vds = BCDataStream()
        serialize_input(vds, self.vin)
        self.addr.serialize(vds)
        vds.write_string(bfh(self.collateral_key))
        vds.write_string(bfh(self.masternode_pubkey))
        vds.write_string(self.sig)
        vds.write_int64(self.sig_time)
        vds.write_uint32(self.protocol_version)
        self.last_ping.serialize(vds)
        vds.write_int64(0)

        return bh2u(vds.input)

    def serialize_for_sig(self, update_time=False):
        """Serialize the message for signing."""
        if update_time:
            self.sig_time = int(time.time())
        s = to_bytes(str(self.addr))
        s += to_bytes(str(self.sig_time))
        s += to_bytes(bfh(self.collateral_key))
        s += to_bytes(bfh(self.masternode_pubkey))
        s += to_bytes(str(self.protocol_version))

        return s

    def get_hash(self):
        vds = BCDataStream()
        vds.write_int64(self.sig_time)
        vds.write_string(bfh(self.collateral_key))
        return hash_encode(bitcoin.sha256d(vds.input))

    def get_collateral_str(self):
        """Get the collateral as a string used to identify this masternode."""
        if not self.vin:
            return
        if not 'prevout_hash' in self.vin or not 'prevout_n' in self.vin:
            return
        return '%s-%d' % (self.vin['prevout_hash'], self.vin['prevout_n'])

    def get_collateral_hash_str(self):
        """Get the collateral as a string used to identify this masternode."""
        if not self.vin:
            return
        if not 'prevout_hash' in self.vin or not 'prevout_n' in self.vin:
            return
        return self.vin['prevout_hash']
      
    @classmethod
    def from_dict(cls, d):
        kwargs = {}
        for key in ['alias', 'vin', 'collateral_key', 'masternode_pubkey', 'sig', 'sig_time',
                    'protocol_version', 'announced']:
            kwargs[key] = d.get(key)

        protocol_version = int(kwargs['protocol_version'])

        vin = kwargs.get('vin')
        if vin:
            kwargs['vin'] = vin
        else:
            kwargs['vin'] = {}

        sig = kwargs.get('sig')
        if sig:
            kwargs['sig'] = base64.b64decode(sig)
        else:
            kwargs['sig'] = ''

        addr = d.get('addr')
        if addr:
            kwargs['addr'] = NetworkAddress.from_dict(addr)
        else:
            kwargs['addr'] = NetworkAddress.from_dict({})

        last_ping = d.get('last_ping')
        if last_ping:
            kwargs['last_ping'] = MasternodePing.from_dict(
                last_ping, protocol_version)
        else:
            kwargs['last_ping'] = MasternodePing.from_dict(
                {}, protocol_version)

        return cls(**kwargs)

    def dump(self):
        kwargs = {}
        for key in ['alias', 'vin', 'collateral_key', 'masternode_pubkey',
                    'sig_time', 'protocol_version', 'announced']:
            kwargs[key] = getattr(self, key)

        if self.sig:
            kwargs['sig'] = base64.b64encode(
                to_bytes(self.sig)).decode('utf-8')
        if self.addr:
            kwargs['addr'] = self.addr.dump()
        if self.last_ping:
            kwargs['last_ping'] = self.last_ping.dump()

        return kwargs

    def sign(self, wif, current_time=None):
        """Sign the masternode announce message.

        If current_time is specified, sig_time will not be updated.
        """
        update_time = True
        if current_time is not None:
            self.sig_time = current_time
            update_time = False

        txin_type, key, is_compressed = bitcoin.deserialize_privkey(wif)
        eckey = bitcoin.regenerate_key(key)
        serialized = self.serialize_for_sig(update_time=update_time)
        self.sig = eckey.sign_message(serialized, is_compressed)
        return self.sig

    def verify(self, addr=None):
        """Verify that our sig is signed with addr's key."""
        if not addr:
            addr = bitcoin.public_key_to_p2pkh(bfh(self.collateral_key))
        return ecc.verify_message_with_address(addr, self.sig, self.serialize_for_sig())