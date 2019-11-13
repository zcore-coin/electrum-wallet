from collections import namedtuple, OrderedDict
import base64
import threading

from decimal import Decimal

from . import ecc
from . import bitcoin
from .blockchain import hash_header
from .masternode import MasternodeAnnounce, NetworkAddress
from .util import AlreadyHaveAddress, print_error, bfh, print_msg, format_satoshis_plain

from .wallet import Standard_Wallet

BUDGET_FEE_CONFIRMATIONS = 6
BUDGET_FEE_TX = 5 * bitcoin.COIN
# From masternode.h
MASTERNODE_MIN_CONFIRMATIONS = 15
MASTERNODE_COLLATERAL_VALUE = 5000 * bitcoin.COIN

MasternodeConfLine = namedtuple('MasternodeConfLine', ('alias', 'addr',
        'wif', 'txid', 'output_index'))

def parse_masternode_conf(lines):
    """Construct MasternodeConfLine instances from lines of a masternode.conf file."""

    conf_lines = []
    for line in lines:
        # Comment.
        if line.startswith('#'):
            continue

        s = line.split(' ')
        if len(s) < 5:
            continue
        alias = s[0]
        addr_str = s[1]
        masternode_wif = s[2]
        collateral_txid = s[3]
        collateral_output_n = s[4]

        # Validate input.
        try:
            txin_type, key, is_compressed = bitcoin.deserialize_privkey(masternode_wif)
            assert key
        except Exception:
            raise ValueError('Invalid masternode private key of alias "%s"' % alias)

        if len(collateral_txid) != 64:
            raise ValueError('Transaction ID of alias "%s" must be 64 hex characters.' % alias)

        try:
            collateral_output_n = int(collateral_output_n)
        except ValueError:
            raise ValueError('Transaction output index of alias "%s" must be an integer.' % alias)

        conf_lines.append(MasternodeConfLine(alias, addr_str, masternode_wif, collateral_txid, collateral_output_n))
    return conf_lines

class MasternodeManager(object):
    """Masternode manager.

    Keeps track of masternode's and helps with signing broadcasts.
    Update: subscriptions are sent through synchronizer
    """
    def __init__(self, wallet, config):
        self.wallet = wallet
        self.config = config
        self.sync = None
        # Subscribed masternode statuses.
        self.masternode_statuses = {}
        self.load()

    def load(self):
        """Load masternode from wallet storage."""
        masternodes = self.wallet.storage.get('masternodes', {})
        self.masternodes = [MasternodeAnnounce.from_dict(d) for d in masternodes.values()]

    def update_masternode_addr(self, alias, ipAddr):
      if not isinstance(alias,str):
        return
      if not isinstance(ipAddr,str):
        return
      if len(ipAddr) > 64:
        return
      addr = ipAddr.split(':')
      if len(addr) != 2:
        return
      addr = NetworkAddress(address=addr[0], port=int(addr[1]))
      updated=False
      for mn in self.masternodes:
        if mn.alias == alias:
          mn.addr = addr
          self.save()
          updated = True
          break
      return updated
          
    def update_masternode_alias(self, aliasOld, aliasNew):
      if not isinstance(aliasOld,str):
        return False
      if not isinstance(aliasNew,str):
        return False
      if len(aliasNew) > 64:
        return False
      updated = False
      for mn in self.masternodes:
        if mn.alias == aliasOld:
          mn.alias = aliasNew
          self.save()
          updated = True
          break
      return updated
          
    def get_masternode(self, alias):
        """Get the masternode labelled as alias."""
        for mn in self.masternodes:
            if mn.alias == alias:
                return mn

    def get_status(self, alias):
        """Get the masternode labelled as alias."""
        print(self.masternode_statuses)
        mx = self.get_masternode(alias)
        if not mx:
          return
        status = self.masternode_statuses.get(mx.vin['prevout_hash'])
        print('.................', status)
        if not status:
          return 'UNKNOWN'
        return status
              
    def get_masternode_by_hash(self, hash_):
        for mn in self.masternodes:
            if mn.get_hash() == hash_:
                return mn

    def add_masternode(self, mn, save = True):
        """Add a new masternode."""
        if any(i.alias == mn.alias for i in self.masternodes):
            raise Exception('A masternode with alias "%s" already exists' % mn.alias)
        self.masternodes.append(mn)
        if save:
            self.save()

    def reload_masternode_sync(self):
      if self.sync:
        self.sync.reload_masternode_task()

    def has_masternode(self, collateral):
      r = False
      for mn in self.masternodes:
        if mn.get_collateral_hash_str() == collateral:
          r = True
          break
      return r
    
    def set_synchornizer_manager(self,synchronizer):
      self.sync = synchronizer

    def remove_masternode(self, alias, save = True):
        """Remove the masternode labelled as alias."""
        mn = self.get_masternode(alias)
        if not mn:
            raise Exception('Nonexistent masternode')
        # Don't delete the delegate key if another masternode uses it too.
        if not any(i.alias != mn.alias and i.masternode_pubkey == mn.masternode_pubkey for i in self.masternodes):
            self.wallet.delete_masternode_delegate(mn.masternode_pubkey)
        tx_coin = "{}:{}".format(mn.vin.get('prevout_hash'),mn.vin.get('prevout_n'))
        self.wallet.set_frozen_state_of_coins([tx_coin], False)
        self.masternodes.remove(mn)
        if self.sync:
          collateral = mn.get_collateral_hash_str()
          if collateral and len(collateral) > 0:
            self.sync.remove_masternode_task(mn.get_collateral_hash_str())
        if save:
            self.save()

    def populate_masternode_output(self, alias):
        """Attempt to populate the masternode's data using its output."""
        mn = self.get_masternode(alias)
        if not mn:
            return
        if mn.announced:
            return
        txid = mn.vin.get('prevout_hash')
        prevout_n = mn.vin.get('prevout_n')
        if not txid or prevout_n is None:
            return
        # Return if it already has the information.
        if mn.collateral_key and mn.vin.get('address') and mn.vin.get('value') == MASTERNODE_COLLATERAL_VALUE:
            return
        if not self.wallet:
            return
        addr = None
        value = None
        
        if isinstance(self.wallet,Standard_Wallet):
          tx = self.wallet.db.get_transaction(txid)
        else:
          tx = self.wallet.transactions.get(txid)
          if not tx:
              return
        if len(tx.outputs()) <= prevout_n:
          return
        _, addr, value = tx.outputs()[prevout_n]
          
        mn.vin['address'] = addr
        mn.vin['value'] = value
        mn.vin['scriptSig'] = ''

        mn.collateral_key = self.wallet.get_public_keys(addr)[0]
        self.save()
        return True

    def get_masternode_collateral_key(self, addr):
        return self.wallet.get_public_keys(addr)[0]

    def get_masternode_outputs(self, domain = None, exclude_frozen = True):
        """Get spendable coins that can be used as masternode collateral."""
        coins = self.wallet.get_utxos(domain, exclude_frozen, mature_only=True, confirmed_only=True)

        coins[:] = [c for c in coins if c.get('value') == MASTERNODE_COLLATERAL_VALUE]

        avaliable_vins = []
        for coin in coins:
            avaliable_vins.append('%s:%d' % (coin.get('prevout_hash'), coin.get('prevout_n', 0xffffffff)))

        used_vins = []
        for mn in self.masternodes:
            used_vins.append('%s:%d' % (mn.vin.get('prevout_hash'), int(mn.vin.get('prevout_n', 0xffffffff))))

        unavaliable_vins = set(avaliable_vins).intersection(used_vins)

        for vin in unavaliable_vins:
            prevout_hash, prevout_n = vin.split(':')
            [coins.remove(c) for c in coins if (c.get('prevout_hash') == prevout_hash) and (c.get('prevout_n') == int(prevout_n))]

        return coins

    def get_masternode_outputs_old(self, domain = None, exclude_frozen = True):
        """Get spendable coins that can be used as masternode collateral."""
        coins = self.wallet.get_utxos(domain, [], exclude_frozen,
                                      mature=True, confirmed_only=True)

        used_vins = map(lambda mn: '%s:%d' % (mn.vin.get('prevout_hash'), mn.vin.get('prevout_n', 0xffffffff)), self.masternodes)
        unused = lambda d: '%s:%d' % (d['prevout_hash'], d['prevout_n']) not in used_vins

        #masternode output
        correct_amount = lambda d: d['value'] == MASTERNODE_COLLATERAL_VALUE

        # Valid outputs have a value of exactly MASTERNODE_COLLATERAL_VALUE SMART and
        # are not in use by an existing masternode.
        is_valid = lambda d: correct_amount(d) and unused(d)

        coins = filter(is_valid, coins)
        return coins

    def get_delegate_privkey(self, pubkey):
        """Return the private delegate key for pubkey (if we have it)."""
        return self.wallet.get_delegate_private_key(pubkey)

    def check_can_sign_masternode(self, alias):
        """Raise an exception if alias can't be signed and announced to the network."""
        mn = self.get_masternode(alias)
        
        if not mn:
            raise Exception('Nonexistent masternode')
        if not mn.vin.get('prevout_hash') and mn.collateral_key:
            raise Exception('Collateral TxId is not specified')
        if not mn.masternode_pubkey:
            raise Exception('Masternode delegate key is not specified')
        if not mn.addr.ip:
            raise Exception('Masternode has no IP address')

        # Ensure that the collateral payment has >= MASTERNODE_MIN_CONFIRMATIONS.
        txinfo = self.wallet.get_tx_height(mn.vin['prevout_hash'])
        height =    txinfo.height
        conf =      txinfo.conf
        timestamp = txinfo.timestamp
        if conf < MASTERNODE_MIN_CONFIRMATIONS:
            raise Exception('Collateral payment must have at least %d confirmations (current: %d)' % (MASTERNODE_MIN_CONFIRMATIONS, conf))
        # Ensure that the Masternode's vin is valid.
        if mn.vin.get('value', 0) != MASTERNODE_COLLATERAL_VALUE:
            raise Exception('Masternode requires a collateral {} SMART output.'.format(MASTERNODE_COLLATERAL_VALUE))

        # Ensure collateral was not moved or spent.
        uxto = '{}:{}'.format(mn.vin['prevout_hash'], mn.vin['prevout_n'])
        utxos = self.wallet.get_addr_utxo(mn.vin['address'])
        if uxto not in utxos:
            raise Exception('Masternode requires a 5 000 ZCR collateral. Check if funds have been moved or spent.')


    def check_masternode_status(self, alias):
        """Raise an exception if alias can't be signed and announced to the network."""
        mn = self.get_masternode(alias)
        if not mn:
            raise Exception('Nonexistent masternode')
        if not mn.vin.get('prevout_hash'):
            raise Exception('Collateral payment is not specified')
        if not mn.collateral_key:
            raise Exception('Collateral key is not specified')
        if not mn.masternode_pubkey:
            raise Exception('Masternode delegate key is not specified')
        if not mn.addr.ip:
            raise Exception('Masternode has no IP address')

        # Ensure that the collateral payment has >= MASTERNODE_MIN_CONFIRMATIONS.
        txinfo = self.wallet.get_tx_height(mn.vin['prevout_hash'])
        height =    txinfo.height
        conf =      txinfo.conf
        timestamp = txinfo.timestamp
        if conf < MASTERNODE_MIN_CONFIRMATIONS:
            raise Exception('Collateral payment must have at least %d confirmations (current: %d)' % (MASTERNODE_MIN_CONFIRMATIONS, conf))
        # Ensure that the Masternode's vin is valid.
        if mn.vin.get('value', 0) != MASTERNODE_COLLATERAL_VALUE:
            raise Exception('Masternode requires a collateral {} SMART output.'.format(MASTERNODE_COLLATERAL_VALUE))

        collat = mn.get_collateral_str()
        status = self.masternode_statuses.get(collat)

        return status

    def save(self):
        """Save masternode's."""
        masternodes = {}
        for mn in self.masternodes:
            masternodes[mn.alias] = mn.dump()
            c = mn.get_collateral_hash_str()
        self.wallet.storage.put('masternodes', masternodes)
        if self.sync:
          self.sync.reload_masternode_task()

    def sign_announce(self, alias, password):
        """Sign a Masternode Announce message for alias."""
        self.check_can_sign_masternode(alias)
        mn = self.get_masternode(alias)
        # Ensure that the masternode's vin is valid.
        if mn.vin.get('scriptSig') is None:
            mn.vin['scriptSig'] = ''
        if mn.vin.get('sequence') is None:
            mn.vin['sequence'] = 0xffffffff
        # Ensure that the masternode's last_ping is current.
        height = self.wallet.get_local_height() - 12
        blockchain = self.wallet.network.blockchain()
        header = blockchain.read_header(height)
        mn.last_ping.block_hash = hash_header(header)
        mn.last_ping.vin = mn.vin
        if not mn.collateral_key and mn.vin:
          mn.collateral_key = mn.vin['prevout_hash']
        # Sign ping with private key.
        self.wallet.sign_masternode_ping(mn.last_ping,mn.masternode_pubkey)
        
        # address = bitcoin.public_key_to_p2pkh(bfh('bfedc9ddfcf8bb7140878e7ffedcc9763e65a865'))
        # After creating the Masternode Ping, sign the Masternode Announce.
        address = bitcoin.public_key_to_p2pkh(bfh(mn.collateral_key))
        mn.sig = self.wallet.sign_message_masternode(
            address, mn, password)
        return mn

    async def send_announce(self, alias):
        """Broadcast a Masternode Announce message for alias to the network.

        Returns a 2-tuple of (error_message, was_announced).
        """
        if not self.wallet.network.is_connected():
            raise Exception('Not connected')

        mn = self.get_masternode(alias)
        # Vector-serialize the masternode.
        serialized = mn.serialize()
        errmsg = []
        callback = lambda r: self.broadcast_announce_callback(alias, errmsg, r)
        await self.wallet.network.send([('masternode.announce.broadcast', [serialized])], callback)
        if errmsg:
            errmsg = errmsg[0]
        return (errmsg, mn.announced)

    def broadcast_announce_callback(self, alias, errmsg, r):
        """Callback for when a Masternode Announce message is broadcasted."""
        print(r)
        try:
            self.on_broadcast_announce(alias, r)
        except Exception as e:
            errmsg.append(str(e))
        finally:
            self.save()

    def on_broadcast_announce(self, alias, r):
        """Validate the server response."""
        mn = self.get_masternode(alias)
        
        if isinstance(r,str):
          msg = r.split(' ')
          if len(msg) < 3:
            raise Exception('Error response: Failed to determine result')
          if ' '.join(msg[0:3]) == 'Masternode broadcast sent':
            mn.announced = True
            return
        elif not isinstance(r,dict):
            raise Exception('Error response: Unknow')
        # dict response
        err = r.get('error')
        if err:
            raise Exception('Error response: %s' % str(err))

        result = r.get('result')

        mn_hash = mn.get_hash()
        mn_dict = result.get(mn_hash)
        if not mn_dict:
            raise Exception('No result for expected Masternode Hash. Got %s' % result)

        if mn_dict.get('errorMessage'):
            raise Exception('Announce was rejected: %s' % mn_dict['errorMessage'])
        if mn_dict.get(mn_hash) != 'successful':
            raise Exception('Announce was rejected (no error message specified)')

        mn.announced = True

    def import_masternode_delegate(self, sec):
        """Import a WIF delegate key.
        An exception will not be raised if the key is already imported.
        """
        try:
            pubkey = self.wallet.import_masternode_delegate(sec)
        except AlreadyHaveAddress:
            txin_type, key, is_compressed = bitcoin.deserialize_privkey(sec)
            pubkey = ecc.ECPrivkey(key)\
                .get_public_key_hex(compressed=is_compressed)
        return pubkey

    def import_masternode_conf_lines(self, conf_lines, password):
        """Import a list of MasternodeConfLine."""
        def already_have(line):
            for masternode in self.masternodes:
                # Don't let aliases collide.
                if masternode.alias == line.alias:
                    return True
                # Don't let outputs collide.
                if masternode.vin.get('prevout_hash') == line.txid and masternode.vin.get('prevout_n') == line.output_index:
                    return True
            return False

        num_imported = 0
        for conf_line in conf_lines:
            if already_have(conf_line):
                continue
            # Import delegate WIF key for signing last_ping.
            public_key = self.import_masternode_delegate(conf_line.wif)

            addr = conf_line.addr.split(':')
            addr = NetworkAddress(address=addr[0], port=int(addr[1]))
            vin = {'prevout_hash': conf_line.txid, 'prevout_n': conf_line.output_index}
            mn = MasternodeAnnounce(alias=conf_line.alias, vin=vin,
                    masternode_pubkey = public_key, addr=addr)
            self.add_masternode(mn)
            try:
                self.populate_masternode_output(mn.alias)
            except Exception as e:
                print_error(str(e))
            num_imported += 1

        return num_imported

    def masternode_subscription_response(self, response):
        """Callback for when a masternode's status changes."""
        if not response:
          return
        if len(response) < 2:
          return
        result = response[1]
        if not result:
          return 
        collateral = result.get('txhash')
        mn = None
        for masternode in self.masternodes:
            if masternode.get_collateral_hash_str() == collateral:
                mn = masternode
                break

        if not mn:
            return
          
        status = result.get('status')
        if status is None:
            status = False
        print_msg('Received updated status for masternode %s: "%s"' % (mn.alias, status))
        self.masternode_statuses[collateral] = status
