#!/usr/bin/env python
from json import loads, dumps
from sys import exit, argv
import base64
try:
    # For Python 3.0 and later
    import requests
except ImportError:
    # Fall back to Python 2's urllib2
    import urllib2 

if len(argv) < 3:
    print('Arguments: <rpc_username> <rpc_password> [<rpc_port>]')
    sys.exit(1)

# From electrum.
def bits_to_target(bits):
        bitsN = (bits >> 24) & 0xff
        if not (0x03 <= bitsN <= 0x1d):
            raise Exception("First part of bits should be in [0x03, 0x1d]")
        bitsBase = bits & 0xffffff
        if not (0x8000 <= bitsBase <= 0x7fffff):
            raise Exception("Second part of bits should be in [0x8000, 0x7fffff]")
        return bitsBase << (8 * (bitsN-3))

  
def rpc(method, params):
    payload = {
        "jsonrpc": "1.0",
        "id":"curltest",
        "method": method,
        "params": params
    }
    
    username = argv[1]
    password = argv[2]
    port = 4561
    if len(argv) > 3:
        port = argv[3]
    url = "http://{}:{}@127.0.0.1:{}/".format(username,password,port)
    
    r = requests.post(url,data=dumps(payload),headers={'content-type': 'application/json'})
    json_response = loads(r.text)
    return json_response

# Electrum checkpoints are blocks 2015, 2015 + 2016, 2015 + 2016*2, ...
i = 2015
INTERVAL = 2016

checkpoints = []
block_count = int(rpc('getblockcount', [])['result'])
print('Blocks: {}'.format(block_count))
while True:
    h = rpc('getblockhash', [i])['result']
    block = rpc('getblock', [h])['result']

    checkpoints.append([
        block['hash'],
        bits_to_target(int(block['bits'], 16))
    ])

    i += INTERVAL
    if i > block_count:
        print('Done.')
        break

with open('checkpoints_output.json', 'w+') as f:
    f.write(dumps(checkpoints, indent=4, separators=(',', ':')))
