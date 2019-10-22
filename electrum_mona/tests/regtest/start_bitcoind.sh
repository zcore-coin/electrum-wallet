#!/usr/bin/env bash
export HOME=~
set -eux pipefail
mkdir -p ~/.zcore
cat > ~/.zcore/zcore.conf <<EOF
regtest=1
txindex=1
printtoconsole=1
rpcuser=doggman
rpcpassword=donkey
rpcallowip=127.0.0.1
zmqpubrawblock=tcp://127.0.0.1:28332
zmqpubrawtx=tcp://127.0.0.1:28333
[regtest]
rpcbind=0.0.0.0
rpcport=19443
EOF
rm -rf ~/.zcore/regtest
screen -S zcored -X quit || true
screen -S zcored -m -d zcored -regtest
sleep 6
addr=$(zcore-cli getnewaddress)
zcore-cli generatetoaddress 150 $addr > /dev/null
