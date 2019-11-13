import os
import traceback
import ecdsa

from PyQt5.QtGui import *
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *

from electrum_mona.i18n import _
from electrum_mona.util import PrintError, bfh
from electrum_mona import constants
from electrum_mona import ecc

from ecdsa.ecdsa import generator_secp256k1
from electrum_mona.bitcoin import EncodeBase58Check, DecodeBase58Check

MASTERNODE_MIN_VERSION = '70922'
MASTERNODE_DEFAULT_PORT = '17293'

class MasternodeControlDialog(QDialog, PrintError):

    CREATE = 0
    EDIT = 1
    VIEW = 2

    def __init__(self, parent=None):
        super(MasternodeControlDialog, self).__init__(parent)
        self.gui = parent
        self.setWindowTitle(_('Masternode Manager'))
        self.waiting_dialog = None
        self.setupUi()

    def setAction(self, action, manager, mapper):

        self.mapper = mapper
        self.manager = manager
        self.action = action

        self.collateralTable.setRowCount(0)
        self.collateralView.removeWidget(self.page)
        self.collateralView.addWidget(self.stackedWidgetPage1)
        self.customMasternodeKeyButton.show()
        self.ipField.setDisabled(False)
        self.aliasField.setDisabled(False)
        self.viewButtonBox.hide()
        self.defaultButtonBox.show()

        if (action == self.VIEW):
            self.collateralView.removeWidget(self.stackedWidgetPage1)
            self.customMasternodeKeyButton.hide()
            self.ipField.setDisabled(True)
            self.aliasField.setDisabled(True)
            self.viewButtonBox.show()
            self.defaultButtonBox.hide()
            self.collateralView.addWidget(self.page)
        elif (action == self.EDIT):
            self.scan_for_outputs(True)
            self.add_current_output()
        elif (action == self.CREATE):
            self.scan_for_outputs(True)
            self.setup_masternodekey_label()

    def setupUi(self):
        self.setObjectName("MasternodeControlDialog")
        self.resize(900, 500)
        sizePolicy = QSizePolicy(QSizePolicy.Preferred, QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.sizePolicy().hasHeightForWidth())
        self.setSizePolicy(sizePolicy)
        self.verticalLayout = QVBoxLayout(self)
        self.verticalLayout.setContentsMargins(20, 20, 20, 20)
        self.verticalLayout.setObjectName("verticalLayout")

        # Grid Layout
        self.gridLayout = QGridLayout()
        self.gridLayout.setObjectName("gridLayout")

        # Alias Label
        self.label_Alias = QLabel(self)
        font = QFont()
        font.setBold(True)
        font.setWeight(75)
        self.label_Alias.setFont(font)
        self.label_Alias.setObjectName("label_Alias")
        self.gridLayout.addWidget(self.label_Alias, 0, 0, 1, 1)

        # Alias Field
        self.aliasField = QLineEdit(self)
        self.aliasField.setAlignment(Qt.AlignCenter)
        self.aliasField.setObjectName("aliasField")
        self.gridLayout.addWidget(self.aliasField, 0, 1, 1, 1)

        # IP Label
        self.label_ipAddress = QLabel(self)
        font = QFont()
        font.setBold(True)
        font.setWeight(75)
        self.label_ipAddress.setFont(font)
        self.label_ipAddress.setObjectName("label_ipAddress")
        self.gridLayout.addWidget(self.label_ipAddress, 1, 0, 1, 1)

        # IP Field
        self.ipField = QLineEdit(self)
        self.ipField.setAlignment(Qt.AlignCenter)
        self.ipField.setObjectName("ipField")
        self.gridLayout.addWidget(self.ipField, 1, 1, 1, 1)

        # Status Label
        self.label_status = QLabel(self)
        font = QFont()
        font.setBold(True)
        font.setWeight(75)
        self.label_status.setFont(font)
        self.label_status.setObjectName("label_status")
        self.gridLayout.addWidget(self.label_status, 2, 0, 1, 1)
        self.label_status.hide()

        # Status Field
        self.statusField = QLineEdit(self)
        self.statusField.setAlignment(Qt.AlignCenter)
        self.statusField.setObjectName("statusField")
        self.statusField.setReadOnly(True)
        self.gridLayout.addWidget(self.statusField, 2, 1, 1, 1)
        self.statusField.hide()

        spacerItem = QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)
        self.gridLayout.addItem(spacerItem, 1, 2, 1, 1)
        spacerItem1 = QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)
        self.gridLayout.addItem(spacerItem1, 0, 2, 1, 1)
        self.verticalLayout.addLayout(self.gridLayout)

        # List or view collateral
        self.collateralView = QStackedWidget(self)
        self.collateralView.setObjectName("collateralView")
        self.create_collateral_list_table()
        self.create_collateral_view_table()
        self.verticalLayout.addWidget(self.collateralView)

        # Masternode Key
        self.verticalLayout_2 = QVBoxLayout()
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.horizontalLayout = QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.label_5 = QLabel(self)
        font = QFont()
        font.setBold(True)
        font.setWeight(75)
        self.label_5.setFont(font)
        self.label_5.setObjectName("label_5")
        self.horizontalLayout.addWidget(self.label_5)
        self.masternodeKeyLabel = QLabel(self)
        font = QFont()
        self.masternodeKeyLabel.setFont(font)
        self.masternodeKeyLabel.setStyleSheet("color: rgb(120, 18, 25);")
        self.masternodeKeyLabel.setTextInteractionFlags(
            Qt.LinksAccessibleByMouse | Qt.TextSelectableByKeyboard | Qt.TextSelectableByMouse)
        self.masternodeKeyLabel.setObjectName("masternodeKeyLabel")
        self.horizontalLayout.addWidget(self.masternodeKeyLabel)

        #Copy Masternode Key Button
        spacerItem7 = QSpacerItem(20, 20, QSizePolicy.Fixed, QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem7)
        self.copyMasternodeKeyButton = QPushButton(self)
        self.copyMasternodeKeyButton.setObjectName("copyMasternodeKeyButton")
        self.horizontalLayout.addWidget(self.copyMasternodeKeyButton)
        self.copyMasternodeKeyButton.clicked.connect(self.copy_masternodekey_label)

        # Custom Masternode Key Button
        self.customMasternodeKeyButton = QPushButton(self)
        self.customMasternodeKeyButton.setObjectName("customMasternodeKeyButton")
        self.horizontalLayout.addWidget(self.customMasternodeKeyButton)
        self.customMasternodeKeyButton.clicked.connect(self.custom_masternode_key)

        # Masternode Message
        spacerItem8 = QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem8)
        self.verticalLayout_2.addLayout(self.horizontalLayout)
        self.label_6 = QLabel(self)
        font = QFont()
        font.setItalic(True)
        self.label_6.setFont(font)
        self.label_6.setAlignment(Qt.AlignLeading | Qt.AlignLeft | Qt.AlignTop)
        self.label_6.setWordWrap(True)
        self.label_6.setObjectName("label_6")
        self.verticalLayout_2.addWidget(self.label_6)
        self.verticalLayout.addLayout(self.verticalLayout_2)
        spacerItem9 = QSpacerItem(20, 20, QSizePolicy.Minimum, QSizePolicy.Fixed)
        self.verticalLayout.addItem(spacerItem9)

        # Close Button
        self.viewButtonBox = QDialogButtonBox(self)
        sizePolicy = QSizePolicy(QSizePolicy.Maximum, QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.viewButtonBox.sizePolicy().hasHeightForWidth())
        self.viewButtonBox.setSizePolicy(sizePolicy)
        self.viewButtonBox.setOrientation(Qt.Horizontal)
        self.viewButtonBox.setStandardButtons(QDialogButtonBox.Close)
        self.viewButtonBox.setObjectName("viewButtonBox")
        self.verticalLayout.addWidget(self.viewButtonBox)
        self.viewButtonBox.hide()
        self.viewButtonBox.clicked.connect(self.reject)

        # Apply or Cancel
        self.defaultButtonBox = QDialogButtonBox(self)
        sizePolicy = QSizePolicy(QSizePolicy.Maximum, QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.defaultButtonBox.sizePolicy().hasHeightForWidth())
        self.defaultButtonBox.setSizePolicy(sizePolicy)
        self.defaultButtonBox.setOrientation(Qt.Horizontal)
        self.defaultButtonBox.setStandardButtons(QDialogButtonBox.Apply | QDialogButtonBox.Cancel)
        self.defaultButtonBox.setObjectName("defaultButtonBox")
        self.verticalLayout.addWidget(self.defaultButtonBox)
        self.defaultButtonBox.clicked.connect(self.handle_apply_cancel)

        self.retranslateUi(self)
        QMetaObject.connectSlotsByName(self)
        self.setTabOrder(self.aliasField, self.ipField)
        self.setTabOrder(self.ipField, self.collateralTable)
        self.setTabOrder(self.collateralTable, self.copyMasternodeKeyButton)

    def create_collateral_list_table(self):
        self.stackedWidgetPage1 = QWidget()
        self.stackedWidgetPage1.setObjectName("stackedWidgetPage1")
        self.verticalLayout_3 = QVBoxLayout(self.stackedWidgetPage1)
        self.verticalLayout_3.setContentsMargins(0, -1, 0, -1)
        self.verticalLayout_3.setObjectName("verticalLayout_3")
        self.label_selectCollateral = QLabel(self.stackedWidgetPage1)
        font = QFont()
        font.setBold(True)
        font.setWeight(75)
        self.label_selectCollateral.setFont(font)
        self.label_selectCollateral.setObjectName("label_4")
        self.verticalLayout_3.addWidget(self.label_selectCollateral)
        self.collateralTable = QTableWidget(self.stackedWidgetPage1)
        font = QFont()
        self.collateralTable.setFont(font)
        self.collateralTable.setColumnCount(5)
        self.collateralTable.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.collateralTable.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.collateralTable.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.collateralTable.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.collateralTable.horizontalHeader().hide()
        self.collateralTable.verticalHeader().hide()
        self.collateralTable.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.collateralTable.setObjectName("collateralTable")
        self.collateralTable.setSortingEnabled(False)
        self.verticalLayout_3.addWidget(self.collateralTable)
        self.collateralView.addWidget(self.stackedWidgetPage1)

    def create_collateral_view_table(self):
        self.page = QWidget()
        self.page.setObjectName("page")
        self.verticalLayout_4 = QVBoxLayout(self.page)
        self.verticalLayout_4.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout_4.setSpacing(10)
        self.verticalLayout_4.setObjectName("verticalLayout_4")
        spacerItem2 = QSpacerItem(20, 10, QSizePolicy.Minimum, QSizePolicy.Maximum)
        self.verticalLayout_4.addItem(spacerItem2)
        self.label_Collateral = QLabel(self.page)
        font = QFont()
        font.setBold(True)
        font.setWeight(75)
        self.label_Collateral.setFont(font)
        self.label_Collateral.setObjectName("label_7")
        self.verticalLayout_4.addWidget(self.label_Collateral)
        self.gridLayout_2 = QGridLayout()
        self.gridLayout_2.setObjectName("gridLayout_2")

        # Tx Address label
        self.label_8 = QLabel(self.page)
        font = QFont()
        font.setBold(True)
        font.setWeight(75)
        self.label_8.setFont(font)
        self.label_8.setObjectName("label_8")
        self.gridLayout_2.addWidget(self.label_8, 0, 0, 1, 1)

        # Tx Address Value
        self.addressViewLabel = QLabel(self.page)
        self.addressViewLabel.setTextInteractionFlags(
            Qt.LinksAccessibleByMouse | Qt.TextSelectableByKeyboard | Qt.TextSelectableByMouse)
        self.addressViewLabel.setObjectName("addressViewLabel")
        self.gridLayout_2.addWidget(self.addressViewLabel, 0, 1, 1, 1)

        # Tx Hash Label
        self.label_9 = QLabel(self.page)
        font = QFont()
        font.setBold(True)
        font.setWeight(75)
        self.label_9.setFont(font)
        self.label_9.setObjectName("label_9")
        self.gridLayout_2.addWidget(self.label_9, 1, 0, 1, 1)

        # Tx Hash Value
        self.txHashViewLabel = QLabel(self.page)
        self.txHashViewLabel.setTextInteractionFlags(
            Qt.LinksAccessibleByMouse | Qt.TextSelectableByKeyboard | Qt.TextSelectableByMouse)
        self.txHashViewLabel.setObjectName("txHashViewLabel")
        self.gridLayout_2.addWidget(self.txHashViewLabel, 1, 1, 1, 1)

        # Tx output index Label
        self.label_10 = QLabel(self.page)
        font = QFont()
        font.setBold(True)
        font.setWeight(75)
        self.label_10.setFont(font)
        self.label_10.setObjectName("label_10")
        self.gridLayout_2.addWidget(self.label_10, 2, 0, 1, 1)

        # Tx output index Value
        self.txIndexViewLabel = QLabel(self.page)
        self.txIndexViewLabel.setTextInteractionFlags(
            Qt.LinksAccessibleByMouse | Qt.TextSelectableByKeyboard | Qt.TextSelectableByMouse)
        self.txIndexViewLabel.setObjectName("txIndexViewLabel")
        self.gridLayout_2.addWidget(self.txIndexViewLabel, 2, 1, 1, 1)

        # Tx value Label
        self.label_txValue = QLabel(self.page)
        font = QFont()
        font.setBold(True)
        font.setWeight(75)
        self.label_txValue.setFont(font)
        self.label_txValue.setObjectName("label_txValue")
        self.gridLayout_2.addWidget(self.label_txValue, 3, 0, 1, 1)
        self.label_txValue.hide()

        # Tx value Value
        self.txValueViewLabel = QLabel(self.page)
        self.txValueViewLabel.setTextInteractionFlags(
            Qt.LinksAccessibleByMouse | Qt.TextSelectableByKeyboard | Qt.TextSelectableByMouse)
        self.txValueViewLabel.setObjectName("txValueViewLabel")
        self.gridLayout_2.addWidget(self.txValueViewLabel, 3, 1, 1, 1)
        self.txValueViewLabel.hide()

        # Tx ScriptSig index Label
        self.label_scriptSig = QLabel(self.page)
        font = QFont()
        font.setBold(True)
        font.setWeight(75)
        self.label_scriptSig.setFont(font)
        self.label_scriptSig.setObjectName("label_scriptSig")
        self.gridLayout_2.addWidget(self.label_scriptSig, 4, 0, 1, 1)
        self.label_scriptSig.hide()

        # Tx ScriptSig index Value
        self.txScriptSigViewLabel = QLabel(self.page)
        self.txScriptSigViewLabel.setTextInteractionFlags(
            Qt.LinksAccessibleByMouse | Qt.TextSelectableByKeyboard | Qt.TextSelectableByMouse)
        self.txScriptSigViewLabel.setObjectName("txScriptSigViewLabel")
        self.gridLayout_2.addWidget(self.txScriptSigViewLabel, 4, 1, 1, 1)
        self.txScriptSigViewLabel.hide()

        # Collateral Key Label
        self.label_collateralKey = QLabel(self.page)
        font = QFont()
        font.setBold(True)
        font.setWeight(75)
        self.label_collateralKey.setFont(font)
        self.label_collateralKey.setObjectName("label_scriptSig")
        self.gridLayout_2.addWidget(self.label_collateralKey, 5, 0, 1, 1)
        self.label_collateralKey.hide()

        # Collateral Key Value
        self.txCollateralKeyLabel = QLabel(self.page)
        self.txCollateralKeyLabel.setTextInteractionFlags(
            Qt.LinksAccessibleByMouse | Qt.TextSelectableByKeyboard | Qt.TextSelectableByMouse)
        self.txCollateralKeyLabel.setObjectName("txCollateralKeyLabel")
        self.gridLayout_2.addWidget(self.txCollateralKeyLabel, 5, 1, 1, 1)
        self.txCollateralKeyLabel.hide()

        spacerItem3 = QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)
        self.gridLayout_2.addItem(spacerItem3, 0, 2, 1, 1)
        spacerItem4 = QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)
        self.gridLayout_2.addItem(spacerItem4, 2, 2, 1, 1)
        spacerItem5 = QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)
        self.gridLayout_2.addItem(spacerItem5, 1, 2, 1, 1)
        self.verticalLayout_4.addLayout(self.gridLayout_2)
        spacerItem6 = QSpacerItem(20, 10, QSizePolicy.Minimum, QSizePolicy.Expanding)
        self.verticalLayout_4.addItem(spacerItem6)
        self.collateralView.addWidget(self.page)

    def retranslateUi(self, MasternodeControlDialog):
        _translate = QCoreApplication.translate
        self.setWindowTitle(_translate("MasternodeControlDialog", "Create new Masternode"))
        self.ipField.setPlaceholderText(_translate("MasternodeControlDialog", "000.000.000.000"))
        self.aliasField.setPlaceholderText(_translate("MasternodeControlDialog", "MyNode1"))
        self.label_ipAddress.setText(_translate("MasternodeControlDialog", "IP-Address"))
        self.label_Alias.setText(_translate("MasternodeControlDialog", "Alias"))
        self.label_status.setText(_translate("MasternodeControlDialog", "Status"))
        self.label_selectCollateral.setText(_translate("MasternodeControlDialog", "Select a collateral for your new node"))
        self.label_Collateral.setText(_translate("MasternodeControlDialog", "Collateral"))
        self.addressViewLabel.setText(_translate("MasternodeControlDialog", "0000000000000000000000000"))
        self.label_8.setText(_translate("MasternodeControlDialog", "Address"))
        self.txIndexViewLabel.setText(_translate("MasternodeControlDialog", "1"))
        self.label_9.setText(_translate("MasternodeControlDialog", "Transaction hash"))
        self.txHashViewLabel.setText(
            _translate("MasternodeControlDialog", "00000000000000000000000000000000000000000000"))
        self.label_10.setText(_translate("MasternodeControlDialog", "Transaction output id"))
        self.label_txValue.setText(_translate("MasternodeControlDialog", "Transaction value"))
        self.txValueViewLabel.setText(
            _translate("MasternodeControlDialog", "00000000"))
        self.label_scriptSig.setText(_translate("MasternodeControlDialog", "Transaction ScriptSig"))
        self.label_collateralKey.setText(_translate("MasternodeControlDialog", "Collateral Key"))
        self.label_5.setText(_translate("MasternodeControlDialog", "Masternode Key"))
        self.masternodeKeyLabel.setText(
            _translate("MasternodeControlDialog", "00000000000000000000000000000000000000000"))
        self.copyMasternodeKeyButton.setText(_translate("MasternodeControlDialog", "Copy MasternodeKey"))
        self.customMasternodeKeyButton.setText(_translate("MasternodeControlDialog", "Custom MasternodeKey"))
        self.label_6.setText(_translate("MasternodeControlDialog",
                                        "Its required to use the \"Masternode Key\" above when you install your new node. You can manually insert it into your node\'s masternode.conf or provide it to the bash installer when prompted."))

    def handle_apply_cancel(self, button):
        sb = self.defaultButtonBox.standardButton(button)
        if sb == QDialogButtonBox.Apply:
            self.save_node()
        elif sb == QDialogButtonBox.Cancel:
            self.reject()

    def save_node(self):

        alias = self.aliasField.text()
        if not alias:
            QMessageBox.critical(self, _('Error'), _("Alias missing."))
            return

        addr = self.ipField.text()
        valid_address = self.validate_addr(addr)
        if not valid_address:
            QMessageBox.critical(self, _('Error'),
                                 _("Invalid IP-Address\n\nRequired format: xxx.xxx.xxx.xxx or xxx.xxx.xxx.xxx:port"))
            return

        collateralTableSelectedItem = self.collateralTable.selectedItems()
        if not collateralTableSelectedItem:
            QMessageBox.critical(self, _('Error'), _("You need to select a collateral."))
            return

        row_index = self.collateralTable.currentRow()
        tx_addr = self.collateralTable.item(row_index,0).text()
        tx_prevout_n = self.collateralTable.item(row_index,1).text()
        tx_hash = self.collateralTable.item(row_index,2).text()
        tx_value = self.collateralTable.item(row_index,3).text()
        tx_collateral_key = self.manager.get_masternode_collateral_key(tx_addr)

        self.txCollateralKeyLabel.setText(tx_collateral_key)
        self.addressViewLabel.setText(tx_addr)
        self.txIndexViewLabel.setText(tx_prevout_n)
        self.txHashViewLabel.setText(tx_hash)
        self.txValueViewLabel.setText(tx_value)
        self.txScriptSigViewLabel.setText('')

        masternode_privkey = str(self.masternodeKeyLabel.text())
        if not masternode_privkey:
            QMessageBox.warning(self, _('Warning'), _('Masternode privkey is empty.'))
            return

        try:
            masternode_pubkey = self.manager.import_masternode_delegate(masternode_privkey)
        except Exception as e:
            # Show an error if the private key is invalid and not an empty string.
            if masternode_privkey:
                QMessageBox.warning(self, _('Warning'), _('Ignoring invalid masternode private key.'))
            masternode_pubkey = ''

        # Save masternode
        tx_coin = "{}:{}".format(tx_hash,tx_prevout_n)
        self.manager.wallet.set_frozen_state_of_coins([tx_coin], True)
        self.mapper.submit()
        self.manager.save()
        self.accept()

    def setup_masternodekey_label(self):
        masternodeKey = self.generate_masternode_key()
        self.masternodeKeyLabel.setText(str(masternodeKey))
z
    def copy_masternodekey_label(self):
        masternodeKey = self.masternodeKeyLabel.text()
        cb = QApplication.clipboard()
        cb.clear(mode=cb.Clipboard)
        cb.setText(masternodeKey, mode=cb.Clipboard)

    def custom_masternode_key(self):
        masternodeKey, ok = QInputDialog.getText(self, 'Custom Masternode Key', 'Insert your key here...')
        if ok:
            if self.validate_masternode_key(masternodeKey):
                self.masternodeKeyLabel.setText(str(masternodeKey))
            else:
                QMessageBox.critical(self, _('Error'), _("Invalid Masternode Key provided\n\n" + masternodeKey))

        else:
            return

    def generate_masternode_key(self):
        G = generator_secp256k1
        _r = G.order()
        pvk = ecdsa.util.randrange(pow(2, 256)) % _r
        privateKey = secret = '%064x'%pvk
        prefix = bytes([constants.net.WIF_PREFIX])
        suffix = b''
        vchIn = prefix + bfh(secret) + suffix
        base58_wif = EncodeBase58Check(vchIn)
        return base58_wif

    def validate_masternode_key(self, key):
        try:
            vch = DecodeBase58Check(key)
            return True
        except BaseException:
            return False

    def validate_addr(self, addr):
        """Get a NetworkAddress instance from this widget's data."""

        ip_field = str(addr)
        port = MASTERNODE_DEFAULT_PORT

        if not ip_field:
            return False

        ip_port = ip_field.split(':')
        ip = ip_port[0]

        if len(ip_port) > 1:
            port = ip_port[1]
        else:
            port = MASTERNODE_DEFAULT_PORT

        return self.validate_ip(ip, port)

    def validate_ip(self, s, p):
        try:
            ip = s.split('.')
            if len(ip) != 4:
                raise Exception('Invalid length')
            for i in ip:
                if int(i) < 0 or int(i) > 255:
                    raise ValueError('Invalid IP byte')
            port = int(p)
        except Exception:
            return False
        return True

    def scan_for_outputs(self, include_frozen):
        """Scan for 5000 ZCORE outputs.

        If one or more is found, populate the list and enable the sign button.
        """
        self.collateralTable.clear()
        exclude_frozen = not include_frozen
        coins = list(self.manager.get_masternode_outputs(exclude_frozen=exclude_frozen))

        self.add_outputs(coins)

    def add_outputs(self, coins):

        self.collateralTable.horizontalHeader().show()
        self.collateralTable.setRowCount(len(coins))
        self.collateralTable.setHorizontalHeaderLabels(("Address;TX-Index;TX-Hash;Value;Height").split(";"))
        self.collateralTable.hideColumn(3)
        self.collateralTable.hideColumn(4)

        if len(coins) > 0:
            for idx, val in enumerate(coins):
                self.collateralTable.setItem(idx, 0, QTableWidgetItem(val.get('address')))
                self.collateralTable.setItem(idx, 1, QTableWidgetItem(str(val.get('prevout_n'))))
                self.collateralTable.setItem(idx, 2, QTableWidgetItem(val.get('prevout_hash')))
                self.collateralTable.setItem(idx, 3, QTableWidgetItem(str(val.get('value'))))
                self.collateralTable.setItem(idx, 4, QTableWidgetItem(str(val.get('height'))))


    def add_current_output(self):
        idx = self.collateralTable.rowCount()
        self.collateralTable.setRowCount(idx+1)
        self.collateralTable.setItem(idx, 0, QTableWidgetItem(self.addressViewLabel.text()))
        self.collateralTable.setItem(idx, 1, QTableWidgetItem(self.txIndexViewLabel.text()))
        self.collateralTable.setItem(idx, 2, QTableWidgetItem(self.txHashViewLabel.text()))
        self.collateralTable.setItem(idx, 3, QTableWidgetItem(self.txValueViewLabel.text()))
        self.collateralTable.setItem(idx, 4, QTableWidgetItem('0'))
        self.collateralTable.selectRow(idx)
