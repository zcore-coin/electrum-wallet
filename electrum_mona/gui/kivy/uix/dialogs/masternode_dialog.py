from kivy.app import App
from kivy.factory import Factory
from kivy.properties import ObjectProperty
from kivy.lang import Builder

from electrum_mona.util import base_units_list
from electrum_mona.i18n import languages
from electrum_mona.gui.kivy.i18n import _
from electrum_mona.plugin import run_hook
from electrum_mona import coinchooser

from .choice_dialog import ChoiceDialog
from .label_dialog import LabelDialog
from .question import Question

from electrum_mona.masternode_manager import parse_masternode_conf 

Builder.load_string('''
#:import partial functools.partial
#:import _ electrum_mona.gui.kivy.i18n._

<AddMasternodeDialog@Popup>
    id: masternode
    title: _('New Masternode')
    disable_pin: False
    use_encryption: False
    BoxLayout:
        orientation: 'vertical'
        ScrollView:
            GridLayout:
                id: scrollviewlayout
                cols:1
                size_hint: 1, None
                height: self.minimum_height
                padding: '10dp'
                SettingsItem:
                    id: alias_setting
                    title: 'Set Alias'
                    description: 'Masternode alias'
                    action: partial(root.set_alias,self)
                CardSeparator
                SettingsItem:
                    id: ip_setting
                    title: 'Set Hot Wallet IP'
                    description: 'Your masternode VPS address'
                    action: partial(root.set_ip,self)
                CardSeparator
                SettingsItem:
                    id: genkey_setting
                    title: 'Set Hot Wallet Key'
                    description: 'Your remote wallet masternode key'
                    action: partial(root.set_genkey,self)
                CardSeparator
                SettingsItem:
                    id: collateral_setting
                    title: 'Set Collateral Tx/Index'
                    description: 'Your collateral transaction'
                    action: partial(root.set_collateral,self)
                CardSeparator
        BoxLayout:
            orientation: 'horizontal'
            size_hint: 1, None
            Button:
        	    text: 'Save'
                size_hint: 1, None
                height: '48dp'
                on_release:
                    root.save()
            Button:
        	    text: 'Cancel'
                size_hint: 1, None
                height: '48dp'
                on_release:
                    root.dismiss()
                    
<MasternodeDialog@Popup>
    id: masternode
    title: _('Masternode Settings - '+ root.alias)
    disable_pin: False
    use_encryption: False
    BoxLayout:
        orientation: 'vertical'
        ScrollView:
            GridLayout:
                id: scrollviewlayout
                cols:1
                size_hint: 1, None
                height: self.minimum_height
                padding: '10dp'
                SettingsItem:
                    id: alias_setting
                    title: 'Alias: ' + str(root.alias)
                    description: 'Masternode alias'
                    action: partial(root.set_alias,self)
                CardSeparator
                SettingsItem:
                    id: ip_setting
                    title: 'Hot Wallet IP: ' + str(root.ip)
                    description: 'Your masternode VPS address'
                    action: partial(root.set_ip,self)
                CardSeparator
                SettingsItem:
                    title: 'Hot Wallet Key: ' + str(root.genkey)
                    description: 'Your remote wallet masternode key'
                    action: partial(root.no_action,self)
                CardSeparator
                SettingsItem:
                    title: 'Collateral Tx/Index: ' + str(root.collateral) + '/' + str(root.collateral_index)
                    description: 'Your collateral transaction'
                    action: partial(root.no_action,self)
                CardSeparator
        BoxLayout:
            orientation: 'horizontal'
            size_hint: 1, None
            Button:
        	    text: 'Start alias'
                size_hint: 1, None
                height: '48dp'
                on_release:
                    root.start()
            Button:
        	    text: 'Remove'
                size_hint: 1, None
                height: '48dp'
                on_release:
                    root.remove()
            Button:
        	    text: 'Close'
                size_hint: 1, None
                height: '48dp'
                on_release:
                    root.dismiss()
''')

class MasternodeDialog(Factory.Popup):
    # mastenode: -> MasternodAnnounce
    def __init__(self, app, masternode):
        # masternode data
        self.alias = masternode.alias
        self.collateral = masternode.vin['prevout_hash']
        self.ip = masternode.addr.ip +':'+str(masternode.addr.port)
        self.collateral_index = str(masternode.vin['prevout_n'])
        self.genkey = ''
        if masternode.masternode_pubkey:
         self.genkey = masternode.masternode_pubkey[:5]+'...'
        self.status = app.masternode.get_status(self.alias)
        print(masternode.dump())
        self.app = app
        self.plugins = self.app.plugins
        self.config = self.app.electrum_config
        Factory.Popup.__init__(self)
        layout = self.ids.scrollviewlayout
        layout.bind(minimum_height=layout.setter('height'))
        # cached dialogs
        self._fx_dialog = None
        self._proxy_dialog = None
        self._language_dialog = None
        self._unit_dialog = None
        self._coinselect_dialog = None
        if not self.app.masternode:
          self.dismiss()
          return

    def update_and_save(self,key,value,do_update=False):
      succ = False
      if key=='ip':
        succ = self.app.masternode.update_masternode_addr(self.alias,value)
        if succ:
          self.ip = value
          self.ids.ip_setting.title = 'Hot Wallet IP: ' + str(self.ip)
      elif key=='alias':
        succ = self.app.masternode.update_masternode_alias(self.alias,value)
        if succ:
          self.alias = value
          self.ids.alias_setting.title = 'Alias: ' + str(self.alias)
          self.title = _('Masternode Settings - '+ self.alias)
      if not succ:
        self.app.show_error(_("Failed to update masternode"))
      elif do_update:
        self.app.update_tabs()
      
    def set_ip(self,item,dt):
      save = lambda v: self.update_and_save('ip',v,True)
      d = LabelDialog(_('Enter VPS IP:Port'), '', save)
      d.open()
    
    def set_alias(self,item,dt):
      save = lambda v: self.update_and_save('alias',v,True)
      d = LabelDialog(_('Enter Alias'), '', save)
      d.open()
    
    def no_action(self,item,dt):
      pass
    
    def _remove(self,resp):
        if not resp:
          return
        if not self.app.masternode:
          self.dismiss()
          return
        self.app.masternode.remove_masternode(self.alias)
        self.app.update_tabs()
        self.dismiss()
    
    def remove(self):
      pwd = lambda resp: self._remove(resp)
      q = Question(_('Are you sure you want to remove: '+self.alias + ' ?'),pwd)
      q.open()
      
    def sign(self,password):
      self.app.masternode.sign_announce(self.alias,password)
      self.announce()
      
    def announce(self):
      self.app.network.run_from_another_thread(self.app.masternode.send_announce(self.alias))
      self.app.update_tabs()
      self.dismiss()
    
    def _start(self,resp):
      if not resp:
        return
      sign = lambda p: self.sign(p) 
      self.app.protected(_("Enter your PIN code to proceed"), sign, ())
   
    def start(self):
        if not self.app.masternode:
          self.dismiss()
          return     
        c = lambda resp: self._start(resp)
        q = Question(_("If your masternode is already ENABLED it'll RESTART, continue ?"),c)
        q.open()
      
class AddMasternodeDialog(Factory.Popup):
    # mastenode: -> MasternodAnnounce
    def __init__(self, app):
        # masternode data
        self.masternode = {
          'alias':None,
          'genkey':None,
          'ip':None,
          'collateral':None,
          'index':None
        }
        self.app = app
        self.plugins = self.app.plugins
        self.config = self.app.electrum_config
        self.outputs = {}
        Factory.Popup.__init__(self)
        layout = self.ids.scrollviewlayout
        layout.bind(minimum_height=layout.setter('height'))
        # cached dialogs
        self._fx_dialog = None
        self._proxy_dialog = None
        self._language_dialog = None
        self._unit_dialog = None
        self._coinselect_dialog = None
        if not self.app.masternode:
          self.dismiss()

    def update_and_save(self,key,value,item):
      self.masternode[key] = value
      item.title = str(value)
      
    def set_ip(self,item,dt):
      save = lambda v: self.update_and_save('ip',v,item)
      d = LabelDialog(_('Enter VPS IP:PORT'), '', save)
      d.open()
    
    def set_alias(self,item,dt):      
      save = lambda v: self.update_and_save('alias',v,item)
      d = LabelDialog(_('Enter Alias'), '', save)
      d.open()
      
    def set_genkey(self,item,dt):
      save = lambda v: self.update_and_save('genkey',v,item)
      d = LabelDialog(_('Enter Masternode Genkey'), '', save)
      d.open()
    
    def set_collateral(self,item,dt):
      coins = list(self.app.masternode.get_masternode_outputs(exclude_frozen=True))
      choices = []
      for val in coins:
        o = val.get('prevout_hash')[:20]+'.../ '+str(val.get('prevout_n'))
        self.outputs[o] = val
        choices.append(o)
      save = lambda v: self.update_and_save('collateral',v,item)
      d = ChoiceDialog(_('Select your masternode collateral/index'), choices, '', save)
      d.open()
    
    def no_action(self,item,dt):
      pass
    
    def missing(self,key):
      self.app.show_error(_("Missing value for: "+key))
      
    def save(self):
        if not self.masternode['alias']:
          self.missing('Alias')
          return
        if not self.masternode['ip']:
          self.missing('IP')
          return
        if not self.masternode['genkey']:
          self.missing('Genkey')
          return
        if not self.masternode['collateral']:
          self.missing('Collateral')
          return
        output = self.outputs[self.masternode['collateral']]
        self.masternode['collateral'] = output['prevout_hash']
        self.masternode['index'] = str(output['prevout_n'])
        c = self.masternode
        try:
          # for now, lets use standard conf line
          line = c['alias']+' '+c['ip']+' '+c['genkey']+' '+c['collateral']+' '+c['index']
          conf_line = parse_masternode_conf([line])
          if not conf_line:
            raise None
          if not self.app.masternode.wallet:
            self.app.masternode.wallet = self.app.wallet
          self.app.masternode.import_masternode_conf_lines(conf_line,None)
          # self.app.wallet.set_frozen_state_of_addresses([c['collateral']], True)
          self.app.wallet.set_frozen_state_of_addresses([c['address']], True)
          self.app.masternode.save()
          self.app.update_tabs()
          self.dismiss()
        except BaseException as e:
            print(e)
            self.app.show_error(_("Failed to create masternode"))
