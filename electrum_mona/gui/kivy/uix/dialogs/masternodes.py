import os

from kivy.app import App
from kivy.factory import Factory
from kivy.properties import ObjectProperty
from kivy.lang import Builder

from electrum_mona.util import base_units
from electrum_mona.storage import StorageReadWriteError

from electrum_mona.masternode_manager import parse_masternode_conf 
from ...i18n import _
from .label_dialog import LabelDialog
from .masternode_dialog import AddMasternodeDialog

Builder.load_string('''
#:import os os
                    
<MasternodesDialog@Popup>:
    title: _('Masternodes')
    id: masternodes
    title: _('Electrum Masternodes')
    disable_pin: False
    use_encryption: False
    BoxLayout:
        orientation: 'vertical'
        padding: '10dp'
        Widget
            size_hint_y: 0.1
        GridLayout:
            cols: 3
            size_hint_y: 0.1
            Button:
                size_hint: 0.1, None
                height: '48dp'
                text: _('New')
                on_release:
                    masternodes.dismiss()
                    root.add_masternode(root.app)
''')

class MasternodesDialog(Factory.Popup):


    def __init__(self, app):
        self.app = app
        self.plugins = self.app.plugins
        self.config = self.app.electrum_config
        Factory.Popup.__init__(self)
        #layout = self.ids.scrollviewlayout
        #layout.bind(minimum_height=layout.setter('height'))
        # cached dialogs
        self._fx_dialog = None
        self._proxy_dialog = None
        self._language_dialog = None
        self._unit_dialog = None
        self._coinselect_dialog = None
        
    def update(self):
        self.wallet = self.app.wallet
        self.disable_pin = self.wallet.is_watching_only() if self.wallet else True
        self.use_encryption = self.wallet.has_password() if self.wallet else False

    def _set_key(self,name,value,prox):
        self.masternode[name] = value
        if callable(prox):
          prox()

    def set_alias(self):
        cb = lambda v: self._set_key('alias',v,self.set_collateral)
        d = LabelDialog(_('Enter alias'), '', cb)
        d.open()
        
    def set_collateral(self):
        cb = lambda v: self._set_key('collateral',v,self.set_collateral_index)
        d = LabelDialog(_('Enter collateral'), '', cb)
        d.open()
        
    def set_collateral_index(self):
        cb = lambda v: self._set_key('index',v,self.set_genkey)
        d = LabelDialog(_('Enter collateral index'), '', cb)
        d.open()
      
    def set_genkey(self):
        cb = lambda v: self._set_key('genkey',v,self.set_addr)
        d = LabelDialog(_('Enter masternode genkey/privkey'), '', cb)
        d.open()
        
    def set_addr(self):
        cb = lambda v: self._set_key('ip',v,self.finalize_masternode)
        d = LabelDialog(_('Enter VPS IP:Port'), '', cb)
        d.open()
        
    def finalize_masternode(self):
        c = self.masternode
        print('finalize ----------> ',c)
        naddress = [c['address']]
        
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
          self.app.wallet.set_frozen_state_of_coins(['{}:{}'.format(c['collateral'],c['index'])], True)
          self.app.masternode.save()
          self.app.update_tabs()
        except Exception as e:
            print(e)
            self.app.show_error(_("Failed to create masternode"))
      
    def add_masternode(self,app):
        d = AddMasternodeDialog(app)
        d.open()
        return 
        self.masternode = {}
        if not app.masternode:
          self.dismmiss()
          return
        if self.app.wallet.is_watching_only():
          self.app.show_error(_('Unlock your wallet.'))
          return
        self.set_alias()

    def _remove_masternode(self,alias):
        if not app.masternode:
          self.dismmiss()
          return
        if self.app.masternode.has_masternode(alias):
          self.app.masternode.remove_masternode(alias)

    def remove_masternode(self,app):
        try:
           cb = lambda v: self._remove_masternode(alias)
           d = LabelDialog(_('Enter Masternode Alias'), '', cb)
           d.open()
        except:
           self.app.show_error(_("R/W error accessing path"))
            
