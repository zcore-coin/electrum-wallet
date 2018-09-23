import shutil
import tempfile

from electrum.storage import WalletStorage
from electrum.wallet import Wallet

from .test_wallet import WalletTestCase


# TODO add other wallet types: 2fa, xpub-only
# TODO hw wallet with client version 2.6.x (single-, and multiacc)
class TestStorageUpgrade(WalletTestCase):

    def test_upgrade_from_client_2_9_3_seeded(self):
        wallet_str = '{"addr_history": {"M86vvgYRgPBW3QfyUnxbKBeUzbGtgp6NXG": [], "M98MvBtibhTcnz8tLPNk3ooFDE5qpck83r": [], "M9caHU9o66Wvmc2gqqW2DHPcnshqdj36kG": [], "MABcFFZv7v3FRAEKU5kqoB6xt9VKupEt8K": [["4dc927c6174608d8a08a9e6182da88010a8bfd3d7ee1ee2e6ce1ab0750a66084", 1244811]], "MAeRNwBYorbvbeAwiJfp7cEiPHThPhcut2": [], "MBMpHGd7nKhFn7SPYkNb2SJd8WiGpTH5aB": [], "MBavRPSte8woScUxXQwybiwvvWNpEZ1WWy": [["63e0cc7890079c623d9dbec3b97c5f827ca31dbc17609a4d9c019deac56a471c", 1244771], ["c8f330a6a0daad48c4ef86cf509658313e7fe400932011bf279619d444b3f9f5", 1244799]], "MC9S8ipqNu4pjodYA7ns6sS15GEEUqeuU3": [], "MEhUENYZXhwuKtiCYep6AjpRGqLBLLxa4y": [], "MFbXqsdyVSnEGmGMpduND5kp93ExhYgtbu": [],"MFgJcgrbEnV1ANbPcAsAV7ADBF63NEpXK3": [], "MGUJMzZeA1PBUsv3rUNcjLzVnAjaWkS95n": [], "MGtCxT8kLcqqi66Spwr98JnYSYJHU7ShGZ": [], "MGwggCpjuwpCfbjTCbYoX1ngzNSUnTEtEn": [], "MLoyw8Bt5zVoVRcFxUPbKuW5FF3NNfLUVf": [], "MLy8usGiKXVqo4VtWAUq1jdgKASdN8JTij": [], "MPMNgAeu7B6PTr9WVM9mhRycmQVy14VUvL": [], "MPQzvFN6fvcdwZC1KsrjagZizdFx46yp1V": [], "MPbw4Njqk6neGMcBNmxHpDjxoBGbMPwJiL": [], "MQycguJjCxpW7qBGKHPptGqMVUP28VJhp6": [], "MRR8gRePoj33M9Sx4UDEAC1fdLhppit71k": [], "MSJTC3sSuVSyQ2Fehrxg5UkwpYQn2bkNjC": [], "MSeTEqGyJfAD6TxsFgfGwMtvWf3fbaRZeW": [], "MSi7o6WRptrcpQEZBvVX2rrZdKz5WHcXyJ": [], "MSjeTpS3Kcij8GvCnatG17mPdFd3FfF3Ra": [], "MTVWS92xnBVqopgTo3F7eYqQq24b3EQpNB": [], "MUuGCeLx98GQxq1Y2UTSQbZd7PMmc2iDAs": [], "MWfHXccPyKPeY5Nf5kSk4GsCKHhsBSymxU": []}, "addresses": {"change": ["MPbw4Njqk6neGMcBNmxHpDjxoBGbMPwJiL", "MPMNgAeu7B6PTr9WVM9mhRycmQVy14VUvL", "MC9S8ipqNu4pjodYA7ns6sS15GEEUqeuU3", "MGwggCpjuwpCfbjTCbYoX1ngzNSUnTEtEn", "MGtCxT8kLcqqi66Spwr98JnYSYJHU7ShGZ", "MRR8gRePoj33M9Sx4UDEAC1fdLhppit71k"], "receiving": ["MBavRPSte8woScUxXQwybiwvvWNpEZ1WWy", "MABcFFZv7v3FRAEKU5kqoB6xt9VKupEt8K", "MGUJMzZeA1PBUsv3rUNcjLzVnAjaWkS95n", "MQycguJjCxpW7qBGKHPptGqMVUP28VJhp6", "MWfHXccPyKPeY5Nf5kSk4GsCKHhsBSymxU", "MAeRNwBYorbvbeAwiJfp7cEiPHThPhcut2", "MSJTC3sSuVSyQ2Fehrxg5UkwpYQn2bkNjC", "M98MvBtibhTcnz8tLPNk3ooFDE5qpck83r", "M9caHU9o66Wvmc2gqqW2DHPcnshqdj36kG", "MBMpHGd7nKhFn7SPYkNb2SJd8WiGpTH5aB", "MSjeTpS3Kcij8GvCnatG17mPdFd3FfF3Ra", "MEhUENYZXhwuKtiCYep6AjpRGqLBLLxa4y", "MLy8usGiKXVqo4VtWAUq1jdgKASdN8JTij", "MFbXqsdyVSnEGmGMpduND5kp93ExhYgtbu", "MSi7o6WRptrcpQEZBvVX2rrZdKz5WHcXyJ", "MFgJcgrbEnV1ANbPcAsAV7ADBF63NEpXK3", "M86vvgYRgPBW3QfyUnxbKBeUzbGtgp6NXG", "MLoyw8Bt5zVoVRcFxUPbKuW5FF3NNfLUVf", "MPQzvFN6fvcdwZC1KsrjagZizdFx46yp1V", "MUuGCeLx98GQxq1Y2UTSQbZd7PMmc2iDAs", "MTVWS92xnBVqopgTo3F7eYqQq24b3EQpNB", "MSeTEqGyJfAD6TxsFgfGwMtvWf3fbaRZeW"]}, "keystore": {"seed": "cereal wise two govern top pet frog nut rule sketch bundle logic", "type": "bip32", "xprv": "xprv9s21ZrQH143K29XjRjUs6MnDB9wXjXbJP2kG1fnRk8zjdDYWqVkQYUqaDtgZp5zPSrH5PZQJs8sU25HrUgT1WdgsPU8GbifKurtMYg37d4v", "xpub": "xpub661MyMwAqRbcEdcCXm1sTViwjBn28zK9kFfrp4C3JUXiW1sfP34f6HA45B9yr7EH5XGzWuTfMTdqpt9XPrVQVUdgiYb5NW9m8ij1FSZgGBF"}, "pruned_txo": {}, "seed_type": "standard", "seed_version": 13, "stored_height": 1244820, "transactions": {"4dc927c6174608d8a08a9e6182da88010a8bfd3d7ee1ee2e6ce1ab0750a66084": "0100000001c2c9a2674e18b405a3da7c8b3517e9ee66d0e0eaea301826851a47b63f7b5892010000009200483045022100cebcf08aa10f780d4de0d615d54d74747a4e0a9d0112ae20d43da24cc65d102602201cc9e12c1f27fad3bf680005c49564460b2234de44b20e5c6814bcdb888ac9cc01475121021a52f873609007d4fbb3762146bcf392a38add103d158b85be84234a6deec95d2102df15712f8b35ca672cd0c7a5ad97581699449cd01a0b0a7ff1e4e8e52f43cb3452aefeffffff01e069f902000000001976a914190c9f5b8dad15b8daa7f1ef821968820980b48e88ac89fe1200", "63e0cc7890079c623d9dbec3b97c5f827ca31dbc17609a4d9c019deac56a471c": "010000000182dc3b573b4b93b02331f9ae63a9d4319d3aa6d408cba9da945559e28b90f1db000000006a47304402203e1826d088c0cd7e04b55392c70beaf14ce4e3f5d29d9d41cbc13492a1369cb102206da8ec16c5159c1a309e65d0cdc2889801e0f4a53e012c9f633c8ee9dc70780f012103581803a5795674e8ba65765d7d8bc4c89ce96835e19538437390b010a0e693f7feffffff01e50bf802000000001976a914286d7ca6a657816ceedb90eecb7afe8f361da39488ac62fe1200", "c8f330a6a0daad48c4ef86cf509658313e7fe400932011bf279619d444b3f9f5": "01000000011c476ac5ea9d019c4d9a6017bc1da37c825f7cb9c3be9d3d629c079078cce063000000006b483045022100fe2b1267e7897cff328a483389606ba74c23073d4a3b09aa1a6b41e66a43729f02206471fa10f6b2a0088bf68bd76432cc36bf6df917adb8bb968c8814e918f05fbc012102276b2411cf66966a9b6198f7e52347cd63a5adfc189cd7681649df4ce433058cfeffffff014585f602000000001976a914b2ca5937a6c75347d3c70a790802efd1b3f14d7d88ac7efe1200"}, "tx_fees": {"4dc927c6174608d8a08a9e6182da88010a8bfd3d7ee1ee2e6ce1ab0750a66084": 100000, "63e0cc7890079c623d9dbec3b97c5f827ca31dbc17609a4d9c019deac56a471c": 100000, "c8f330a6a0daad48c4ef86cf509658313e7fe400932011bf279619d444b3f9f5": 100000}, "txi": {"4dc927c6174608d8a08a9e6182da88010a8bfd3d7ee1ee2e6ce1ab0750a66084": {}, "63e0cc7890079c623d9dbec3b97c5f827ca31dbc17609a4d9c019deac56a471c": {}, "c8f330a6a0daad48c4ef86cf509658313e7fe400932011bf279619d444b3f9f5": {"MBavRPSte8woScUxXQwybiwvvWNpEZ1WWy": [["63e0cc7890079c623d9dbec3b97c5f827ca31dbc17609a4d9c019deac56a471c:0", 49810405]]}}, "txo": {"4dc927c6174608d8a08a9e6182da88010a8bfd3d7ee1ee2e6ce1ab0750a66084": {"MABcFFZv7v3FRAEKU5kqoB6xt9VKupEt8K": [[0, 49900000, false]]}, "63e0cc7890079c623d9dbec3b97c5f827ca31dbc17609a4d9c019deac56a471c": {"MBavRPSte8woScUxXQwybiwvvWNpEZ1WWy": [[0, 49810405, false]]}, "c8f330a6a0daad48c4ef86cf509658313e7fe400932011bf279619d444b3f9f5": {}}, "use_encryption": false, "verified_tx3": {"4dc927c6174608d8a08a9e6182da88010a8bfd3d7ee1ee2e6ce1ab0750a66084": [1244811, 1518548087, 2], "63e0cc7890079c623d9dbec3b97c5f827ca31dbc17609a4d9c019deac56a471c": [1244771, 1518545016, 1], "c8f330a6a0daad48c4ef86cf509658313e7fe400932011bf279619d444b3f9f5": [1244799, 1518547429, 1]}, "wallet_type": "standard", "winpos-qt": [1016, 143, 840, 400]}'
        self._upgrade_storage(wallet_str)

    def test_upgrade_from_client_2_9_3_importedkeys(self):
        wallet_str = '{"addr_history": {"MJNDhNyzYPbcFE5uZAg2j6YyUQVdLDhuP3": []}, "addresses": {"change": [], "receiving": ["MJNDhNyzYPbcFE5uZAg2j6YyUQVdLDhuP3"]}, "keystore": {"keypairs": {"03c2725dae5de0cbf0101cf57a3aadfb301bc3b432fa8ea38515198e41df12199f": "TPxZYPTaBiwFVo5kVmBYuJctGVDMRaCLNEEu8nsxLednda1zmVGS"}, "type": "imported"}, "pruned_txo": {}, "seed_version": 13, "stored_height": 1244824, "transactions": {}, "tx_fees": {}, "txi": {}, "txo": {}, "use_encryption": false, "verified_tx3": {}, "wallet_type": "standard", "winpos-qt": [314, 230, 840, 400]}'
        self._upgrade_storage(wallet_str)

    def test_upgrade_from_client_2_9_3_watchaddresses(self):
        wallet_str = '{"addr_history": {"MFMy9FwJsV6HiN5eZDqDETw4pw52q3UGrb": []}, "addresses": ["MFMy9FwJsV6HiN5eZDqDETw4pw52q3UGrb"], "pruned_txo": {}, "seed_version": 13, "stored_height": 1244820, "transactions": {}, "tx_fees": {}, "txi": {}, "txo": {}, "verified_tx3": {}, "wallet_type": "imported", "winpos-qt": [100, 100, 840, 400]}'
        self._upgrade_storage(wallet_str)

    def test_upgrade_from_client_2_9_3_multisig(self):
        wallet_str = '{"addr_history": {"P8jgDdDDshff1QpvMvpBWvQ6eNzxCUtPzt": [], "P9gS5tcr9DrKJBXhoCsttz4z3f8Rc1JNsp": [], "PAh6JWaw5rhTjiuy3oA3qPxw9VMP7WHFG9": [["92587b3fb6471a85261830eaeae0d066eee917358b7cdaa305b4184e67a2c9c2", 1244811], ["4dc927c6174608d8a08a9e6182da88010a8bfd3d7ee1ee2e6ce1ab0750a66084", 1244811]], "PCBauNwA3Cv7pSX4w2Jo5gqeFAjmuSPzFz": [], "PDQnZfcGTT8NxjLxDnUBywmHTAiaUA1eaW": [], "PEB5ypNYcqahQR1pVZPKyvXV6D1fowzaWW": [], "PELNR4HeSFqaY175fBwfCtfRMc7xxEwzrA": [], "PFNhoTkyVt6pnwM8SPvKz7p1i31FT47TMf": [], "PFiuNDiPJ7KfswEHbt86Kgzmu1MyGEifAo": [], "PKUd3FD55GhWuB2YYXouv6tdyzMk868A99": [], "PMCQaLUfGqGjSk931W1DnqMakjN7BNphzd": [], "PMaHpXqBxb4t8ugM4Pck7cVTVG7c7LNVhm": [], "PPsdnu4wwnmzr8gvpcTJAfeCb1f1LdRT1p": [], "PQSVheR3xP32bnviHAoUdBivmupxqVrpkm": [], "PRwQwsMR1doV435PTAmEX4YiR4KPCpD5tW": [], "PSR9rkJGNN6sp3YfNcL4SVshM6urNyDbEN": [], "PSs5WAEBaS5LfVxUBDBGzaqEZvmwpbUaRq": [], "PSsxMiTNivb2bZhHYcXQEPQXiD2RRiikrW": [], "PTNCJhHMBPG3RVVJ6rGXfSnvLg9HMD7VA8": [], "PUGX2QjJBiq8CMTcf1MfgA2nMdYB8UZVib": [], "PUZdh3MNKX7qT9eWDmguoiDudU2SNhQbGd": [], "PUfNE6rBYjGewm6HT3U1t1QrgeDuJhTa4v": [], "PUgxpEyhTz5wXBgan6HoBDRxndkszkRzsw": [], "PUwsdVq7dyQGTdjWaqYxdVkP9kMtpoA2Uz": [], "PVderjbckPSqkN33hw5B4gBsrKD4tb7mAp": [], "PViDr7H8qhgvW8ajY8teTFYzFMWQ9C25CQ": [], "PXu1FBDpr7XVpoKUQ6HZDQzuNz8V3fCRww": []}, "addresses": {"change": ["PUwsdVq7dyQGTdjWaqYxdVkP9kMtpoA2Uz", "PUfNE6rBYjGewm6HT3U1t1QrgeDuJhTa4v", "PPsdnu4wwnmzr8gvpcTJAfeCb1f1LdRT1p", "PMCQaLUfGqGjSk931W1DnqMakjN7BNphzd", "PVderjbckPSqkN33hw5B4gBsrKD4tb7mAp", "P9gS5tcr9DrKJBXhoCsttz4z3f8Rc1JNsp"], "receiving": ["PAh6JWaw5rhTjiuy3oA3qPxw9VMP7WHFG9", "PKUd3FD55GhWuB2YYXouv6tdyzMk868A99", "PUZdh3MNKX7qT9eWDmguoiDudU2SNhQbGd", "PUGX2QjJBiq8CMTcf1MfgA2nMdYB8UZVib", "PRwQwsMR1doV435PTAmEX4YiR4KPCpD5tW", "PSsxMiTNivb2bZhHYcXQEPQXiD2RRiikrW", "PCBauNwA3Cv7pSX4w2Jo5gqeFAjmuSPzFz", "PDQnZfcGTT8NxjLxDnUBywmHTAiaUA1eaW", "PEB5ypNYcqahQR1pVZPKyvXV6D1fowzaWW", "PUgxpEyhTz5wXBgan6HoBDRxndkszkRzsw", "PQSVheR3xP32bnviHAoUdBivmupxqVrpkm", "PTNCJhHMBPG3RVVJ6rGXfSnvLg9HMD7VA8", "PViDr7H8qhgvW8ajY8teTFYzFMWQ9C25CQ", "PXu1FBDpr7XVpoKUQ6HZDQzuNz8V3fCRww", "PMaHpXqBxb4t8ugM4Pck7cVTVG7c7LNVhm", "PSs5WAEBaS5LfVxUBDBGzaqEZvmwpbUaRq", "PFiuNDiPJ7KfswEHbt86Kgzmu1MyGEifAo", "P8jgDdDDshff1QpvMvpBWvQ6eNzxCUtPzt", "PELNR4HeSFqaY175fBwfCtfRMc7xxEwzrA", "PSR9rkJGNN6sp3YfNcL4SVshM6urNyDbEN", "PFNhoTkyVt6pnwM8SPvKz7p1i31FT47TMf"]}, "pruned_txo": {}, "seed_version": 13, "stored_height": 1244820, "transactions": {"4dc927c6174608d8a08a9e6182da88010a8bfd3d7ee1ee2e6ce1ab0750a66084": "0100000001c2c9a2674e18b405a3da7c8b3517e9ee66d0e0eaea301826851a47b63f7b5892010000009200483045022100cebcf08aa10f780d4de0d615d54d74747a4e0a9d0112ae20d43da24cc65d102602201cc9e12c1f27fad3bf680005c49564460b2234de44b20e5c6814bcdb888ac9cc01475121021a52f873609007d4fbb3762146bcf392a38add103d158b85be84234a6deec95d2102df15712f8b35ca672cd0c7a5ad97581699449cd01a0b0a7ff1e4e8e52f43cb3452aefeffffff01e069f902000000001976a914190c9f5b8dad15b8daa7f1ef821968820980b48e88ac89fe1200", "92587b3fb6471a85261830eaeae0d066eee917358b7cdaa305b4184e67a2c9c2": "0200000001393444c30c55cbad286d4d23772d026b73c24865fa8dba894b611c21d95f077d010000006a47304402207f0df76f0105de92d02ec69f39b41682b6c5c984ea6c61b427a0f170ab5855cc022001b3369c652c367890744f3469b54e66f71db8c64182b16f45b0e0db63e5c2ac0121034db136fd5fe036ba9c95170947dc1302f98d48e4fec816d15f2ce35fa4a5ebe2feffffff0294512303000000001976a9142df179daddeea6fbc0bc582758bdcde728a6429288ac80f0fa020000000017a914170eb2491149d327a42f983fb6be32fe889c710f8789fe1200"}, "tx_fees": {"4dc927c6174608d8a08a9e6182da88010a8bfd3d7ee1ee2e6ce1ab0750a66084": 100000, "92587b3fb6471a85261830eaeae0d066eee917358b7cdaa305b4184e67a2c9c2": 23004}, "txi": {"4dc927c6174608d8a08a9e6182da88010a8bfd3d7ee1ee2e6ce1ab0750a66084": {"PAh6JWaw5rhTjiuy3oA3qPxw9VMP7WHFG9": [["92587b3fb6471a85261830eaeae0d066eee917358b7cdaa305b4184e67a2c9c2:1", 50000000]]}, "92587b3fb6471a85261830eaeae0d066eee917358b7cdaa305b4184e67a2c9c2": {}}, "txo": {"4dc927c6174608d8a08a9e6182da88010a8bfd3d7ee1ee2e6ce1ab0750a66084": {}, "92587b3fb6471a85261830eaeae0d066eee917358b7cdaa305b4184e67a2c9c2": {"PAh6JWaw5rhTjiuy3oA3qPxw9VMP7WHFG9": [[1, 50000000, false]]}}, "use_encryption": false, "verified_tx3": {"4dc927c6174608d8a08a9e6182da88010a8bfd3d7ee1ee2e6ce1ab0750a66084": [1244811, 1518548087, 2], "92587b3fb6471a85261830eaeae0d066eee917358b7cdaa305b4184e67a2c9c2": [1244811, 1518548087, 1]}, "wallet_type": "1of2", "winpos-qt": [201, 254, 840, 400], "x1/": {"seed": "speed cruise market wasp ability alarm hold essay grass coconut tissue recipe", "type": "bip32", "xprv": "xprv9s21ZrQH143K48ig2wcAuZoEKaYdNRaShKFR3hLrgwsNW13QYRhXH6gAG1khxim6dw2RtAzF8RWbQxr1vvWUJFfEu2SJZhYbv6pfreMpuLB", "xpub": "xpub661MyMwAqRbcGco98y9BGhjxscP7mtJJ4YB1r5kUFHQMNoNZ5y1mptze7J37JypkbrmBdnqTvSNzxL7cE1FrHg16qoj9S12MUpiYxVbTKQV"}, "x2/": {"type": "bip32", "xprv": null, "xpub": "xpub661MyMwAqRbcGrCDZaVs9VC7Z6579tsGvpqyDYZEHKg2MXoDkxhrWoukqvwDPXKdxVkYA6Hv9XHLETptfZfNpcJZmsUThdXXkTNGoBjQv1o"}}'
        self._upgrade_storage(wallet_str)

##########

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        from electrum.plugin import Plugins
        from electrum.simple_config import SimpleConfig

        cls.electrum_path = tempfile.mkdtemp()
        config = SimpleConfig({'electrum_path': cls.electrum_path})

        gui_name = 'cmdline'
        # TODO it's probably wasteful to load all plugins... only need Trezor
        Plugins(config, True, gui_name)

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        shutil.rmtree(cls.electrum_path)

    def _upgrade_storage(self, wallet_json, accounts=1):
        storage = self._load_storage_from_json_string(wallet_json, manual_upgrades=True)

        if accounts == 1:
            self.assertFalse(storage.requires_split())
            if storage.requires_upgrade():
                storage.upgrade()
                self._sanity_check_upgraded_storage(storage)
        else:
            self.assertTrue(storage.requires_split())
            new_paths = storage.split_accounts()
            self.assertEqual(accounts, len(new_paths))
            for new_path in new_paths:
                new_storage = WalletStorage(new_path, manual_upgrades=False)
                self._sanity_check_upgraded_storage(new_storage)

    def _sanity_check_upgraded_storage(self, storage):
        self.assertFalse(storage.requires_split())
        self.assertFalse(storage.requires_upgrade())
        w = Wallet(storage)

    def _load_storage_from_json_string(self, wallet_json, manual_upgrades=True):
        with open(self.wallet_path, "w") as f:
            f.write(wallet_json)
        storage = WalletStorage(self.wallet_path, manual_upgrades=manual_upgrades)
        return storage
