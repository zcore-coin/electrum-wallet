MAX_TARGET = 0x00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff

class Target:

    def convbits(new_target):
        c = ("%064x" % int(new_target))[2:]
        while c[:2] == '00' and len(c) > 6:
            c = c[2:]
        bitsN, bitsBase = len(c) // 2, int('0x' + c[:6], 16)
        if bitsBase >= 0x800000:
            bitsN += 1
            bitsBase >>= 8
        new_bits = bitsN << 24 | bitsBase
        return new_bits
        
    def convbignum(bits):
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
        first = self.read_header(height - 1056 - 1 if height > 1056 else 0)
        if first is None:
            first = chain.get(height - 1056 - 1 if height > 1056 else 0)
        last = self.read_header(height - 1)
        if last is None:
            last = chain.get(height - 1)
        assert last is not None
        # bits to target
        bits = last.get('bits')
        target = Target.convbignum(bits)
        if height % 1056 != 0:
            return bits, target
        # new target
        nActualTimespan = last.get('timestamp') - first.get('timestamp')
        nTargetTimespan = 95040; #1.1 days 1.1*24*60*60
        nActualTimespan = max(nActualTimespan, nTargetTimespan // 4)
        nActualTimespan = min(nActualTimespan, nTargetTimespan * 4)
        new_target = min(MAX_TARGET, (target*nActualTimespan) // nTargetTimespan)
        # convert new target to bits
        new_bits = Target.convbits(new_target)
        return new_bits, new_target

        
    def kgw(self, height, chain=None):	#from vertcoin thanks https://github.com/vertcoin/electrum-vtc

        if chain is None:
            chain = {}

        BlocksTargetSpacing			= 1.5 * 60; # 1.5 minutes
        TimeDaySeconds				= 60 * 60 * 24;
        PastSecondsMin				= TimeDaySeconds * 0.25;
        PastSecondsMax				= TimeDaySeconds * 7;
        PastBlocksMin				    = PastSecondsMin // BlocksTargetSpacing;
        PastBlocksMax				    = PastSecondsMax // BlocksTargetSpacing;

        BlockReadingIndex             = height - 1
        BlockLastSolvedIndex          = height - 1
        TargetBlocksSpacingSeconds    = BlocksTargetSpacing
        PastRateAdjustmentRatio       = 1.0
        bnProofOfWorkLimit = MAX_TARGET
    	  
        if (BlockLastSolvedIndex<=0 or BlockLastSolvedIndex<PastSecondsMin):
            new_target = bnProofOfWorkLimit
            new_bits = Target.convbits(new_target)      
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
                PastDifficultyAverage=Target.convbignum(reading.get('bits'))
            else:
                PastDifficultyAverage= float((Target.convbignum(reading.get('bits')) - PastDifficultyAveragePrev) / float(i)) + PastDifficultyAveragePrev;

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
        new_bits = Target.convbits(new_target)

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
        bnNew = Target.convbignum(bits)
        if height % AdjustmentInterval != 0:
            return bits, bnNew

        # retarget
        bnNew *= nActualTimespan
        bnNew //= TargetTimespan
        bnNew = min(bnNew, MAX_TARGET)

        new_bits = Target.convbits(bnNew)
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
                    PastDifficultyAverage = Target.convbignum(BlockReading.get('bits'))
                else:
                    bnNum = Target.convbignum(BlockReading.get('bits'))
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

        new_bits = Target.convbits(bnNew)
        return new_bits, bnNew

