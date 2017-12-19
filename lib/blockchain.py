# Electrum - lightweight Bitcoin client
# Copyright (C) 2012 thomasv@ecdsa.org
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import os
import threading

from . import util
from . import bitcoin
from .bitcoin import *

MAX_TARGET = 0x00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff

try:
    import lyra2re2_hash
except ImportError as e:
    exit("Please run 'sudo pip3 install https://github.com/metalicjames/lyra2re-hash-python/archive/master.zip'")

try:
    import scrypt
    scryptGetHash = lambda x: scrypt.hash(x, x, N=1024, r=1, p=1, buflen=32)
except ImportError:
    util.print_msg("Warning: package scrypt not available, using fallback")
    from .scrypt import scrypt_1024_1_1_80 as scryptGetHash

def serialize_header(res):
    s = int_to_hex(res.get('version'), 4) \
        + rev_hex(res.get('prev_block_hash')) \
        + rev_hex(res.get('merkle_root')) \
        + int_to_hex(int(res.get('timestamp')), 4) \
        + int_to_hex(int(res.get('bits')), 4) \
        + int_to_hex(int(res.get('nonce')), 4)
    return s

def deserialize_header(s, height):
    hex_to_int = lambda s: int('0x' + bh2u(s[::-1]), 16)
    h = {}
    h['version'] = hex_to_int(s[0:4])
    h['prev_block_hash'] = hash_encode(s[4:36])
    h['merkle_root'] = hash_encode(s[36:68])
    h['timestamp'] = hex_to_int(s[68:72])
    h['bits'] = hex_to_int(s[72:76])
    h['nonce'] = hex_to_int(s[76:80])
    h['block_height'] = height
    return h

def hash_header(header):
    if header is None:
        return '0' * 64
    if header.get('prev_block_hash') is None:
        header['prev_block_hash'] = '00'*32
    return hash_encode(Hash(bfh(serialize_header(header))))

blockchains = {}

def read_blockchains(config):
    blockchains[0] = Blockchain(config, 0, None)
    fdir = os.path.join(util.get_headers_dir(config), 'forks')
    if not os.path.exists(fdir):
        os.mkdir(fdir)
    l = filter(lambda x: x.startswith('fork_'), os.listdir(fdir))
    l = sorted(l, key = lambda x: int(x.split('_')[1]))
    for filename in l:
        checkpoint = int(filename.split('_')[2])
        parent_id = int(filename.split('_')[1])
        b = Blockchain(config, checkpoint, parent_id)
        h = b.read_header(b.checkpoint)
        if b.parent().can_connect(h, check_height=False):
            blockchains[b.checkpoint] = b
        else:
            util.print_error("cannot connect", filename)
    return blockchains

def check_header(header):
    if type(header) is not dict:
        return False
    for b in blockchains.values():
        if b.check_header(header):
            return b
    return False

def can_connect(header):
    for b in blockchains.values():
        if b.can_connect(header):
            return b
    return False


class Blockchain(util.PrintError):
    """
    Manages blockchain headers and their verification
    """

    def __init__(self, config, checkpoint, parent_id):
        self.config = config
        self.catch_up = None # interface catching up
        self.checkpoint = checkpoint
        self.checkpoints = bitcoin.NetworkConstants.CHECKPOINTS
        self.parent_id = parent_id
        self.lock = threading.Lock()
        with self.lock:
            self.update_size()

    def parent(self):
        return blockchains[self.parent_id]

    def get_max_child(self):
        children = list(filter(lambda y: y.parent_id==self.checkpoint, blockchains.values()))
        return max([x.checkpoint for x in children]) if children else None

    def get_checkpoint(self):
        mc = self.get_max_child()
        return mc if mc is not None else self.checkpoint

    def get_branch_size(self):
        return self.height() - self.get_checkpoint() + 1

    def get_name(self):
        return self.get_hash(self.get_checkpoint()).lstrip('00')[0:10]

    def check_header(self, header):
        header_hash = hash_header(header)
        height = header.get('block_height')
        return header_hash == self.get_hash(height)

    def fork(parent, header):
        checkpoint = header.get('block_height')
        self = Blockchain(parent.config, checkpoint, parent.checkpoint)
        open(self.path(), 'w+').close()
        self.save_header(header)
        return self

    def height(self):
        return self.checkpoint + self.size() - 1

    def size(self):
        with self.lock:
            return self._size

    def update_size(self):
        p = self.path()
        self._size = os.path.getsize(p)//80 if os.path.exists(p) else 0

    def verify_header(self, header, prev_hash, bits, target):
        height = header.get('block_height')
        if prev_hash != header.get('prev_block_hash'):
            raise BaseException("prev hash mismatch: %s vs %s" % (prev_hash, header.get('prev_block_hash')))
        if height % 2016 != 0 and height // 2016 < len(self.checkpoints):
            return
        if bitcoin.NetworkConstants.TESTNET:
            return
        if height < 450000 :
            _powhash = rev_hex(bh2u(scryptGetHash(bfh(serialize_header(header)))))
        else:
            _powhash = rev_hex(bh2u(lyra2re2_hash.getPoWHash(bfh(serialize_header(header)))))
        if bits != header.get('bits'):
            raise BaseException("bits mismatch: %s vs %s" % (bits, header.get('bits')))
        if int('0x' + _powhash, 16) > target:
            raise BaseException("insufficient proof of work: %s vs target %s" % (int('0x' + _powhash, 16), target))

    def verify_chunk(self, index, data):
        num = len(data) // 80
        prev_hash = self.get_hash(index * 2016 - 1)
        if index != 0:
            prev_header = self.read_header(index * 2016 - 1)
        headers = {}
        for i in range(num):
            raw_header = data[i*80:(i+1) * 80]
            header = deserialize_header(raw_header, index*2016 + i)
            headers[header.get('block_height')] = header
            bits, target = self.get_target(index*2016 + i, headers)
            self.verify_header(header, prev_hash, bits, target)
            prev_hash = hash_header(header)

    def path(self):
        d = util.get_headers_dir(self.config)
        filename = 'blockchain_headers' if self.parent_id is None else os.path.join('forks', 'fork_%d_%d'%(self.parent_id, self.checkpoint))
        return os.path.join(d, filename)

    def save_chunk(self, index, chunk):
        filename = self.path()
        d = (index * 2016 - self.checkpoint) * 80
        if d < 0:
            chunk = chunk[-d:]
            d = 0
        self.write(chunk, d)
        self.swap_with_parent()

    def swap_with_parent(self):
        if self.parent_id is None:
            return
        parent_branch_size = self.parent().height() - self.checkpoint + 1
        if parent_branch_size >= self.size():
            return
        self.print_error("swap", self.checkpoint, self.parent_id)
        parent_id = self.parent_id
        checkpoint = self.checkpoint
        parent = self.parent()
        with open(self.path(), 'rb') as f:
            my_data = f.read()
        with open(parent.path(), 'rb') as f:
            f.seek((checkpoint - parent.checkpoint)*80)
            parent_data = f.read(parent_branch_size*80)
        self.write(parent_data, 0)
        parent.write(my_data, (checkpoint - parent.checkpoint)*80)
        # store file path
        for b in blockchains.values():
            b.old_path = b.path()
        # swap parameters
        self.parent_id = parent.parent_id; parent.parent_id = parent_id
        self.checkpoint = parent.checkpoint; parent.checkpoint = checkpoint
        self._size = parent._size; parent._size = parent_branch_size
        # move files
        for b in blockchains.values():
            if b in [self, parent]: continue
            if b.old_path != b.path():
                self.print_error("renaming", b.old_path, b.path())
                os.rename(b.old_path, b.path())
        # update pointers
        blockchains[self.checkpoint] = self
        blockchains[parent.checkpoint] = parent

    def write(self, data, offset):
        filename = self.path()
        with self.lock:
            with open(filename, 'rb+') as f:
                if offset != self._size*80:
                    f.seek(offset)
                    f.truncate()
                f.seek(offset)
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            self.update_size()

    def save_header(self, header):
        delta = header.get('block_height') - self.checkpoint
        data = bfh(serialize_header(header))
        assert delta == self.size()
        assert len(data) == 80
        self.write(data, delta*80)
        self.swap_with_parent()

    def read_header(self, height):
        assert self.parent_id != self.checkpoint
        if height < 0:
            return
        if height < self.checkpoint:
            return self.parent().read_header(height)
        if height > self.height():
            return
        delta = height - self.checkpoint
        name = self.path()
        if os.path.exists(name):
            with open(name, 'rb') as f:
                f.seek(delta * 80)
                h = f.read(80)
        if h == bytes([0])*80:
            return None
        return deserialize_header(h, height)

    def get_hash(self, height):
        if height == -1:
            return '0000000000000000000000000000000000000000000000000000000000000000'
        if height == 0:
            return bitcoin.NetworkConstants.GENESIS
        elif height < len(self.checkpoints) * 2016:
            assert (height+1) % 2016 == 0
            index = height // 2016
            h, t = self.checkpoints[index]
            return h
        else:
            return hash_header(self.read_header(height))


    def convbits(self,new_target):
        c = ("%064x" % int(new_target))[2:]
        while c[:2] == '00' and len(c) > 6:
            c = c[2:]
        bitsN, bitsBase = len(c) // 2, int('0x' + c[:6], 16)
        if bitsBase >= 0x800000:
            bitsN += 1
            bitsBase >>= 8
        new_bits = bitsN << 24 | bitsBase
        return new_bits
        
    def convbignum(self,bits):
        MM = 256*256*256
        a = bits%MM
        if a < 0x8000:
            a *= 256
        target = (a) * pow(2, 8 * (bits//MM - 3))
        return target


    def ltc(self, height, chain=None):
        if height < 1056:
            return 0x1e0ffff0, MAX_TARGET
        # Litecoin: go back the full period unless it's the first retarget
        first = chain.get(height - 1056 - 1 if height > 1056 else 0)
        if first is None:
            first = self.read_header(height - 1056 - 1 if height > 1056 else 0)
        last = chain.get(height - 1)
        if last is None:
            last = self.read_header(height - 1)
        assert last is not None
        # bits to target
        bits = last.get('bits')
        target = self.convbignum(bits)
        if height % 1056 != 0:
            return bits, target
        # new target
        nActualTimespan = last.get('timestamp') - first.get('timestamp')
        nTargetTimespan = 95040; #1.1 days 1.1*24*60*60
        nActualTimespan = max(nActualTimespan, nTargetTimespan // 4)
        nActualTimespan = min(nActualTimespan, nTargetTimespan * 4)
        new_target = min(MAX_TARGET, (target*nActualTimespan) // nTargetTimespan)
        # convert new target to bits
        new_bits = self.convbits(new_target)
        return new_bits, new_target

        
    def kgw(self, height, chain=None):	#from vertcoin thanks https://github.com/vertcoin/electrum-vtc

        if chain is None:
            chain = {}

        BlocksTargetSpacing			= 90; # 1.5 minutes
        TimeDaySeconds				= 86400; #60 * 60 * 24
        PastSecondsMin				= 21600; #TimeDaySeconds * 0.25
        PastSecondsMax				= 604800; #TimeDaySeconds * 7
        PastBlocksMin				    = PastSecondsMin // BlocksTargetSpacing;
        PastBlocksMax				    = PastSecondsMax // BlocksTargetSpacing;

        BlockReadingIndex             = height - 1
        BlockLastSolvedIndex          = height - 1
        TargetBlocksSpacingSeconds    = BlocksTargetSpacing
        PastRateAdjustmentRatio       = 1.0
        bnProofOfWorkLimit = MAX_TARGET
          
        if (BlockLastSolvedIndex<=0 or BlockLastSolvedIndex<PastSecondsMin):
            new_target = bnProofOfWorkLimit
            new_bits = self.convbits(new_target)      
            return new_bits, new_target

        last = chain.get(BlockLastSolvedIndex)
        if last == None:
            last = self.read_header(BlockLastSolvedIndex)
          
        for i in range(1,int(PastBlocksMax)+1):
            PastBlocksMass=i

            reading = chain.get(BlockReadingIndex)
            if reading == None:
                reading = self.read_header(BlockReadingIndex)
                chain[BlockReadingIndex] = reading

            if (reading == None or last == None):
                raise BaseException("Could not find previous blocks when calculating difficulty reading: " + str(BlockReadingIndex) + ", last: " + str(BlockLastSolvedIndex) + ", height: " + str(height))
            
            if (i == 1):
                PastDifficultyAverage=self.convbignum(reading.get('bits'))
            else:
                PastDifficultyAverage= float((self.convbignum(reading.get('bits')) - PastDifficultyAveragePrev) / float(i)) + PastDifficultyAveragePrev;

            PastDifficultyAveragePrev = PastDifficultyAverage;
            PastRateActualSeconds   = last.get('timestamp') - reading.get('timestamp');
            PastRateTargetSeconds   = TargetBlocksSpacingSeconds * PastBlocksMass;
            PastRateAdjustmentRatio       = 1.0
            if (PastRateActualSeconds < 0):
                PastRateActualSeconds = 0.0
            if (PastRateActualSeconds != 0 and PastRateTargetSeconds != 0):
                PastRateAdjustmentRatio			= float(PastRateTargetSeconds) / float(PastRateActualSeconds)
            EventHorizonDeviation       = 1 + (0.7084 * pow(float(PastBlocksMass)/float(144), -1.228))
            EventHorizonDeviationFast   = EventHorizonDeviation
            EventHorizonDeviationSlow		= float(1) / float(EventHorizonDeviation)
            if (PastBlocksMass >= PastBlocksMin):
            
                if ((PastRateAdjustmentRatio <= EventHorizonDeviationSlow) or (PastRateAdjustmentRatio >= EventHorizonDeviationFast)):
                    break;
                 
                if (BlockReadingIndex<1):
                    break
                
            BlockReadingIndex = BlockReadingIndex -1;

        bnNew   = PastDifficultyAverage
        if (PastRateActualSeconds != 0 and PastRateTargetSeconds != 0):
            bnNew *= float(PastRateActualSeconds);
            bnNew //= float(PastRateTargetSeconds);
            
        if (bnNew > bnProofOfWorkLimit):
            bnNew = bnProofOfWorkLimit

        # new target
        new_target = bnNew
        new_bits = self.convbits(new_target)

        return new_bits, new_target


    def dgsld(self, height, chain=None):
        if chain is None:
            chain = {}

        nPowTargetTimespan = 95040 #1.1 days 1.1*24*60*60

        nPowTargetSpacing = 90 #1.5 minute
        nPowTargetSpacingDigisheld = 90 #1.5 minute

        DifficultyAdjustmentIntervalDigisheld = nPowTargetSpacingDigisheld // nPowTargetSpacing #1

        AdjustmentInterval = DifficultyAdjustmentIntervalDigisheld

        blockstogoback = AdjustmentInterval - 1
        if (height != AdjustmentInterval):
            blockstogoback = AdjustmentInterval

        last_height = height - 1
        first_height = last_height - blockstogoback

        TargetTimespan = nPowTargetSpacingDigisheld

        first = chain.get(first_height)
        if first is None:
            first = self.read_header(first_height)
        last = chain.get(last_height)
        if last is None:
            last = self.read_header(last_height)

        nActualTimespan = last.get('timestamp') - first.get('timestamp')

        nActualTimespan = TargetTimespan + int(float(nActualTimespan - TargetTimespan) / float(8))
        nActualTimespan = max(nActualTimespan, TargetTimespan - int(float(TargetTimespan) / float(4)))
        nActualTimespan = min(nActualTimespan, TargetTimespan + int(float(TargetTimespan) / float(2)))

        bits = last.get('bits')
        bnNew = self.convbignum(bits)
        if height % AdjustmentInterval != 0:
            return bits, bnNew

        # retarget
        bnNew *= nActualTimespan
        bnNew //= TargetTimespan
        bnNew = min(bnNew, MAX_TARGET)

        new_bits = self.convbits(bnNew)
        return new_bits, bnNew


    def dgwv3(self, height, chain=None):

        last = chain.get(height - 1)
        if last is None:
            last = self.read_header(height - 1)

        # params
        BlockLastSolved = last
        BlockReading = last
        BlockCreating = height
        nActualTimespan = 0
        LastBlockTime = 0
        PastBlocksMin = 24
        PastBlocksMax = 24
        CountBlocks = 0
        PastDifficultyAverage = 0
        PastDifficultyAveragePrev = 0
        bnNum = 0

        #thanks watanabe!! http://askmona.org/5288#res_61
        if BlockLastSolved is None or height-1 < 450024:
            return 0x1e0fffff, MAX_TARGET
        for i in range(1, PastBlocksMax + 1):
            CountBlocks += 1

            if CountBlocks <= PastBlocksMin:
                if CountBlocks == 1:
                    PastDifficultyAverage = self.convbignum(BlockReading.get('bits'))
                else:
                    bnNum = self.convbignum(BlockReading.get('bits'))
                    PastDifficultyAverage = ((PastDifficultyAveragePrev * CountBlocks)+(bnNum)) // (CountBlocks + 1)
                PastDifficultyAveragePrev = PastDifficultyAverage

            if LastBlockTime > 0:
                Diff = (LastBlockTime - BlockReading.get('timestamp'))
                nActualTimespan += Diff
            LastBlockTime = BlockReading.get('timestamp')

            BlockReading = chain.get((height-1) - CountBlocks)
            if BlockReading is None:
                BlockReading = self.read_header((height-1) - CountBlocks)


        bnNew = PastDifficultyAverage
        nTargetTimespan = CountBlocks * 90 #1.5 miniutes

        nActualTimespan = max(nActualTimespan, nTargetTimespan//3)
        nActualTimespan = min(nActualTimespan, nTargetTimespan*3)

        # retarget
        bnNew *= nActualTimespan
        bnNew //= nTargetTimespan
        bnNew = min(bnNew, MAX_TARGET)

        new_bits = self.convbits(bnNew)
        return new_bits, bnNew


    def get_target(self, height, chain=None):
        if bitcoin.NetworkConstants.TESTNET:
            return 0, 0
        elif height // 2016 < len(self.checkpoints):
            h, t = self.checkpoints[height // 2016]
            return self.convbits(t[1]),t
        elif height < 80000:
            return self.ltc(height, chain)
        elif height < 140000:
            return self.kgw(height, chain)
        elif height < 450000:
            return self.dgsld(height, chain)
        elif height == 1187424:
            return 453037678,MAX_TARGET
        elif height == 1187425:
            return 453049761,MAX_TARGET
        elif height == 1187426:
            return 453056689,MAX_TARGET
        elif height == 1187427:
            return 453053493,MAX_TARGET
        elif height == 1187428:
            return 453055081,MAX_TARGET
        elif height == 1187429:
            return 453060145,MAX_TARGET
        elif height == 1187430:
            return 453057892,MAX_TARGET
        elif height == 1187431:
            return 453050162,MAX_TARGET
        elif height == 1187432:
            return 453044709,MAX_TARGET
        elif height == 1187433:
            return 453040779,MAX_TARGET
        elif height == 1187434:
            return 453037232,MAX_TARGET
        elif height == 1187435:
            return 453036347,MAX_TARGET
        elif height == 1187436:
            return 453036792,MAX_TARGET
        elif height == 1187437:
            return 453041932,MAX_TARGET
        elif height == 1187438:
            return 453042568,MAX_TARGET
        elif height == 1187439:
            return 453041078,MAX_TARGET
        elif height == 1187440:
            return 453044014,MAX_TARGET
        elif height == 1187441:
            return 453045182,MAX_TARGET
        elif height == 1187442:
            return 453039075,MAX_TARGET
        elif height == 1187443:
            return 453051430,MAX_TARGET
        elif height == 1187444:
            return 453055157,MAX_TARGET
        elif height == 1187445:
            return 453054651,MAX_TARGET
        elif height == 1187446:
            return 453054972,MAX_TARGET
        elif height == 1187447:
            return 453054904,MAX_TARGET
        elif height == 1187448:
            return 453044917,MAX_TARGET
        else:
            return self.dgwv3(height, chain)


    def can_connect(self, header, check_height=True):
        height = header['block_height']
        if check_height and self.height() != height - 1:
            #self.print_error("cannot connect at height", height)
            return False
        if height == 0:
            return hash_header(header) == bitcoin.NetworkConstants.GENESIS
        try:
            prev_hash = self.get_hash(height - 1)
        except:
            return False
        if prev_hash != header.get('prev_block_hash'):
            return False
        headers = {}
        headers[header.get('block_height')] = header
        bits, target = self.get_target(height, headers)
        try:
            self.verify_header(header, prev_hash, bits, target)
        except BaseException as e:
            return False
        return True

    def connect_chunk(self, idx, hexdata):
        try:
            data = bfh(hexdata)
            self.verify_chunk(idx, data)
            #self.print_error("validated chunk %d" % idx)
            self.save_chunk(idx, data)
            return True
        except BaseException as e:
            self.print_error('verify_chunk failed', str(e))
            return False

    def get_checkpoints(self):
        # for each chunk, store the hash of the last block and the target after the chunk
        cp = []
        n = self.height() // 2016
        for index in range(n):
            h = self.get_hash((index+1) * 2016 -1)
            target = self.get_target(index * 2016)
            cp.append((h, target))
        return cp
