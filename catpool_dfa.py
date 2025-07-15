import os
import sys
import random
import subprocess
import struct
import datetime
from collections import deque
import signal
import time

def processinput(iblock, blocksize):
    """processinput() helper function
   iblock: int representation of one input block
   blocksize: int (8 for DES, 16 for AES)
   returns: (bytes to be used as target stdin, a list of strings to be used as args for the target)
   default processinput(): returns (None, one string containing the block in hex)
   return (None, None) if input can't be injected via stdin or args
"""
    return (None, ['%0*x' % (2*blocksize, iblock)])
# Example to provide input as raw chars on stdin:
#    return (bytes.fromhex('%0*x' % (2*blocksize, iblock)), None)

def processoutput(output, blocksize):
    """processoutput() helper function
   output: string, textual output of the target
   blocksize: int (8 for DES, 16 for AES)
   returns a int, supposed to be the data block outputted by the target
   default processouput(): expects the output to be directly the block in hex
"""
    # DFA is only possible in presence of output so this function is supposed
    # to return an output under normal conditions.
    # It will be wrapped by try_processoutput so no need to care about faults
    # leading to situations without exploitable output.
    return int(output, 16)

def try_processoutput(processoutput):
    def foo(output, blocksize):
        try:
            return processoutput(output, blocksize)
        except:
            return None
    return foo
from collections import defaultdict
def group_from_aligned_lists(correct_list, faulty_list, output_file="grouped_output.txt"):
    assert len(correct_list) == len(faulty_list), "List lengths must match."

    groups = defaultdict(list)

    for c, c_star in zip(correct_list, faulty_list):
        R = c[1]
        R_star = c_star[1]
        diffl = c[0]^c_star[0]
        
        diff = R ^ R_star^diffl
        groups[diff].append((c, c_star))

    with open(output_file, "w") as f:
        for diff, pair_list in sorted(groups.items()):
            
            f.write(f"diff in the right: {hex(diff)}\n")
            for c, cf in pair_list:
                f.write(f"{c},#")
                f.write(f"diff in the left: {hex(c[0]^cf[0])}\n")
            for _, c_star in pair_list:
                f.write(f"{c_star},\n")
            f.write("\n")  # separate groups

    print(f"Grouped results written to {output_file}")
class Acquisition:
    def __init__(self, targetbin, targetdata, goldendata, dfa,
                iblock=0x74657374746573747465737474657374,
                processinput=processinput,
                processoutput=processoutput,
                verbose=1,
                maxleaf=256*256,
                minleaf=64,
                minleafnail=8,
                addresses=None,
                start_from_left=True,
                depth_first_traversal=False,
                faults=4,
                faultval=1,
                minfaultspercol=4,
                timeoutfactor=2,
                savetraces_format='default',
                logfile=None,
                tolerate_error=False,
                encrypt=None,
                outputbeforelastrounds=False,
                shell=False,
                debug=False):
        self.digcount = 0
        self.correctct=[]
        self.correctcts=[]
        self.faultycts=[]
        self.fixedtable = None
        self.debug=debug
        self.verbose=verbose
        self.tolerate_error=tolerate_error
        self.outputbeforelastrounds=outputbeforelastrounds
        self.encrypt=encrypt
        self.shell=shell
        self.faultval = faultval # fixing input fault
        if self.verbose>1:
            print("Initializing...")
        # Challenge binary
        self.targetbin = targetbin
        # Tables are in same binary or elsewhere? Beware targetdata gets destroyed!
        self.targetdata = targetdata
        # Gold reference, must be different from targetdata
        self.goldendata=open(goldendata, 'rb').read()
        # Check function, to validate corrupted outputs
        self.dfa = dfa
        # Block size in bytes AES:16, DES:8
        self.blocksize=dfa.blocksize
        # Enum from dfa class
        self.FaultStatus=dfa.FaultStatus
        # Ref iblock
        self.iblock=iblock
        # prepares iblock as list of strings based on its int representation
        self.processinput = processinput
        # from output bytes returns oblock as int
        self.processoutput = processoutput
        # If program may crash, make sure try_processoutput() returns None in such cases
        self.try_processoutput = try_processoutput(processoutput)
        # Largest (aligned) block to fault
        self.maxleaf=maxleaf
        # Smallest (aligned) block to fault in discovery phase
        self.minleaf=minleaf
        # Smallest (aligned) block to fault in nail-down phase
        self.minleafnail=minleafnail
        # Tables addresses range:
        # None               = full range
        # (0x1000,0x5000)    = target only specified address range
        # '/path/to/logfile' = replays address ranges specified in this log file
        self.addresses = addresses
        # Start faults from the left part or the right part of the range?
        self.start_from_left=start_from_left
        # Depth-first traversal or breadth-first traversal?
        self.depth_first_traversal=depth_first_traversal
        # What faults to try once we've a good candidate position?
        # list of values to XOR: [0x01, 0xff, ...], or number of random faults
        self.faults=faults
        # How many faults per column do we want before stopping?
        self.minfaultspercol=minfaultspercol
        # Timestamp
        self.inittimestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        # Timeout factor (if target execution is N times slower than usual it gets killed)
        self.timeoutfactor=timeoutfactor
        # Traces format: 'default' / 'trs'
        self.savetraces_format = savetraces_format
        # Logfile
        self.logfilename=logfile
        self.logfile=None
        self.lastroundkeys=[]
        def sigint_handler(signal, frame):
            print('\nGot interrupted!')
            self.savetraces()
            os.remove(self.targetdata)
            if self.logfile is not None:
                self.logfile.close()
            sys.exit(0)
        def sigusr1_handler(signal, frame):
            self.savetraces()
        signal.signal(signal.SIGINT, sigint_handler)
        signal.signal(signal.SIGUSR1, sigusr1_handler)
        self.timeout=10
        if self.verbose>1:
            print("Initialized!")
        if self.verbose>0:
            print('Press Ctrl+C to interrupt')
            print('Send SIGUSR1 to dump intermediate results file: $ kill -SIGUSR1 %i' % os.getpid())

    def savetraces(self):
        if len(self.encpairs) <= 1:
            # print(self.digcount)
            print('No trace to save, sorry')
            return ([], [])
        if self.savetraces_format=='default':
            return self.savedefault()
        elif self.savetraces_format == 'trs':
            return self.savetrs()
        else:
            print('Error: unknown format: '+ self.savetraces_format)

    def savedefault(self):
        tracefiles=([], [])
        print("len of encpairs")
        print(len(self.encpairs))
        for goodpairs, mode in [(self.encpairs, "enc")]:
            if len(goodpairs) > 1:
                tracefile='dfa_%s_%s-%s_%i.txt' % (mode, self.inittimestamp, datetime.datetime.now().strftime('%H%M%S'), len(goodpairs))
                print('Saving %i traces in %s' % (len(goodpairs), tracefile))
                with open(tracefile, 'wb') as f:
                    for (iblock, oblock) in goodpairs:
                        f.write(('%0*X  ' % (8, iblock)).encode('utf8'))
                        f.write(('%0*X %0*X   ' % (4, oblock[0], 4, oblock[1])).encode('utf8'))
                        f.write(('right diff:%0*X\n' % (4,self.correctct[1]^oblock[1])).encode('utf8'))
                tracefiles[mode=="dec"].append(tracefile)
        return tracefiles

    def savetrs(self):
        tracefiles=([], [])
        for goodpairs, mode in [(self.encpairs, "enc")]:
            if len(goodpairs) > 1:
                trsfile='trs_%s_%s-%s_%i.trs' % (mode, self.inittimestamp, datetime.datetime.now().strftime('%H%M%S'), len(goodpairs))
                print('Saving %i traces in %s' % (len(goodpairs), trsfile))
                with open(trsfile, 'wb') as trs:
                    # Nr of traces
                    trs.write(b'\x41\x04' + struct.pack('<I', len(goodpairs)))
                    # Nr of samples
                    trs.write(b'\x42\x04' + struct.pack('<I', 0))
                    # Sample Coding
                    trs.write(b'\x43\x01\x01')
                    # Length of crypto data
                    trs.write(b'\x44\x02' + struct.pack('<H', 2*self.blocksize))
                    # End of header
                    trs.write(b'\x5F\x00')
                    for (iblock, oblock) in goodpairs:
                        # crypto data
                        trs.write(iblock.to_bytes(self.blocksize,'big')+oblock.to_bytes(self.blocksize,'big'))
                tracefiles[mode=="dec"].append(trsfile)
        return tracefiles

    def doit(self, table, processed_input, protect=True, init=False, lastroundkeys=None,counter=0):
        input_stdin, input_args_int = processed_input
        input_args=[]
        diff=None
        for i in input_args_int:
            i+=counter
            input_args.append(str(i))
        # print("input:"+str(input_args))
        # print(input_args)
        if input_stdin is None:
            input_stdin=b''
        if input_args is None:
            input_args=[]
        if lastroundkeys is None:
            lastroundkeys=self.lastroundkeys
        # To avoid seldom busy file errors:
        if os.path.isfile(self.targetdata):
            os.remove(self.targetdata)
        open(self.targetdata, 'wb').write(table)
        if os.path.normpath(self.targetbin) == os.path.normpath(self.targetdata):
            os.chmod(self.targetbin,0o755)
        if self.debug:
            print('echo -n "'+input_stdin.hex()+'"|xxd -r -p|'+' '.join([self.targetbin] + input_args))
        try:
            if self.tolerate_error:
                proc = subprocess.Popen(' '.join([self.targetbin] + input_args) + '; exit 0', stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, executable='/bin/bash')
            elif self.shell:
                proc = subprocess.Popen(' '.join([self.targetbin] + input_args), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, executable='/bin/bash')
            else:
                # print(type(self.targetbin))
                # print(type(input_args[0]))
                proc = subprocess.Popen([self.targetbin] + input_args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output, errs = proc.communicate(input=input_stdin, timeout=self.timeout)
        except OSError:
            return (None, self.FaultStatus.Crash,None)
        except subprocess.TimeoutExpired:
            proc.terminate()
            try:
                proc.communicate(timeout=self.timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
            except:
                pass
            return (None, self.FaultStatus.Loop,None)
        if self.debug:
            print(output)
        if protect:
            oblock=self.try_processoutput(output, self.blocksize)
        else:
            oblock=self.processoutput(output, self.blocksize)
        if oblock is not None and len(oblock) > 2:
            oblock = None
        if self.debug:
            print(oblock)
            sys.exit(0)
        if oblock is None:
            return (None, self.FaultStatus.Crash,None)
        if len(oblock) != 2:
            return (None, self.FaultStatus.Crash,None)
        else:
            # print(type(oblock))
            # print(len(oblock))
            
            # oblock = self.dfa.int2bytes(oblock)
            # oblocktmp = self.dfa.rewind(oblock, lastroundkeys, self.encrypt)
            status,diff=self.dfa.check(oblock, self.encrypt, self.verbose, init)
            
            # print("status:"+str(status))
            # oblock = oblocktmp if self.outputbeforelastrounds else oblock
            # oblock = self.dfa.bytes2int(oblock)
        # return (oblock, status, index) # in the case of SPECK, we dont need index and other shits
        return oblock, status,diff

    def splitrange(self, r, mincut=1):
        x,y=r
        if y-x <= self.maxleaf and mincut == 0:
            return deque([r])
        # Let's split range into power of two and remaining
        left=1<<(((y-x-1)//2)).bit_length()
        if mincut>0:
            mincut=mincut-1
        dq=self.splitrange((x,x+left), mincut)
        dq.extend(self.splitrange((x+left,y), mincut))
        return dq

    def inject(self, r, faultfct):
        
        # print("In function inject()")
        # print(sys.getsizeof(self.goldendata[r[0]:r[1]]))
    
        # return self.goldendata[:r[0]]+bytes([faultfct(x) for x in self.goldendata[r[0]:r[0]+1]])+self.goldendata[r[0]:] # 

        # if r[1]<r[0]+self.minleafnail:
        return self.goldendata[:r[0]]+bytes([faultfct(x) for x in self.goldendata[r[0]:r[1]]])+self.goldendata[r[1]:] #

        # return self.goldendata[:r[0]]+bytes([faultfct(x) for x in self.goldendata[r[0]:r[1]]])+self.goldendata[r[1]:] # 
    
    
    
    def inject_byte(self, r, faultfct):
        
        # self.goldendata[r[0]]^=faultval
        # return self.goldendata[:r[0]]+self.goldendata[r[0]+1:] #injects a value 

        # if r[1]<r[0]+self.minleafnail:
        return self.goldendata[:r[0]]+bytes([faultfct(x) for x in self.goldendata[r[0]:r[0]+1]])+bytes([faultfct(x) for x in self.goldendata[r[0]:r[1]]])+self.goldendata[r[1]:] #

        # return self.goldendata[:r[0]]+bytes([faultfct(x) for x in self.goldendata[r[0]:r[1]]])+self.goldendata[r[1]:] #


    def inject_bit_level(self, r, bit_index, mode="flip"):
        if isinstance(r, int):
            r = (r, r + 1)

        assert r[1] > r[0], "illegal range"
        assert r[1] <= len(self.goldendata), "out of list"
        assert 0 <= bit_index <= 7, "bit_index should be in [0,7]"

        data = bytearray(self.goldendata)  # copy data
        # print("-------new----------")
        for i in range(r[0], r[1]):
            
            # original = data[i]
            if mode == "flip":
                print("data["+str(i)+"]:"+str(data[i]))
                data[i] ^= (1 << (7 - bit_index))
                print("inject_bit_level:"+str(data[i])+" ^ "+str(self.goldendata[i])+" = "+str(bin((data[i])^self.goldendata[i])))
               
                print("data["+str(i)+"]:"+str(data[i]))
                break
            elif mode == "set":
                data[i] |= (1 << (7 - bit_index))
            elif mode == "clear":
                data[i] &= ~(1 << (7 - bit_index))
            elif mode == "mask":
                data[i] &= (1 << (7 - bit_index))
            else:
                raise ValueError(f"unknown mode: {mode}")
        return bytes(data)

    def dig(self, tree=None, faults=None, level=0, candidates=[]):
        if tree is None:
            tree=self.tabletree
        if faults is None:
            faults=self.faults
        if not self.depth_first_traversal:
            breadth_first_level_address=None
        count=0
        star = 0
        start, end = [0,0]
        # while len(tree) > 0:
        if self.addresses==None:
            r = tree.popleft() if self.start_from_left else tree.pop()
            start, end = r
        else:
            r = self.addresses
            start, end = r
        print(r)
        for byte_addr in range(start, end,16):
            for bit_pos in range(8):
                fault_desc = f"bit{bit_pos}"

                try:
                    print("address:"+str(hex(byte_addr))+" ["+str(bit_pos)+"]")
                    table = self.inject_bit_level((byte_addr, byte_addr + 1), bit_pos)
                except Exception as e:
                    if self.verbose > 0:
                        print(f"[!] Injection failed at 0x{byte_addr:08X} bit {bit_pos}: {e}")
                    continue
                
                oblock, status, diff = self.doit(table, self.processed_input)
                        # print("correct:"+str(oblockct))
                # print("faulty:"+str(oblockft))
                print("status"+str(status))
                log = 'Lvl %03i [0x%08X.%d] %s %0*X ->' % (
                    level, byte_addr, bit_pos, fault_desc, int(self.blocksize), self.iblock)

                if oblock is not None:
                    log += ' %0*X %0*X' % (
                        int(self.blocksize / 2), oblock[0],
                        int(self.blocksize / 2), oblock[1])

                log += ' ' + status.name

                if status in [self.FaultStatus.GoodEncFault]:
                    log += ' left_diff:' + str(diff[0])
                    log += ' right_diff:' + str(diff[1])
                    self.faultycts.append(oblock)
                    self.encpairs.append((self.iblock, oblock))

                if self.verbose > 41:
                    print(log)

                if status in [self.FaultStatus.GoodEncFault]:
                    # Optional deeper analysis like in dig()
                    diffls = []
                    diffrs = []
                    mark = 0
                    for i in range(100):
                        if star % 100 == 0:
                            print("*", end="", flush=True)
                        star+=1
                        oblockct, statusct, _ = self.doit(self.goldendata, self.processed_input, protect=False, init=False, counter=i)
                        oblockft, statusft, _ = self.doit(table, self.processed_input, protect=False, init=False, counter=i)
                        # print("correct:"+str(oblockct),end=" ")
                        # print("faulty:"+str(oblockft),end=" ,")
                        if oblockft is None or oblockct is None or statusft != self.FaultStatus.GoodEncFault:
                            continue

                        diffr = oblockct[0] ^ oblockct[1] ^ oblockft[0] ^ oblockft[1]
                        diffl = oblockct[0] ^ oblockft[0]

                        
                        if diffr == 0 or diffl==0:
                                continue
                        diffls.append(diffl)
                        diffrs.append(diffr)
                        print("check:["+str(hex(oblockct[0]))+","+str(hex(oblockct[1]))+"],"+"["+str(hex(oblockft[0]))+","+str(hex(oblockft[1]))+"]"+"         "+str(hex(diffl))+","+str(hex(diffr)))
                                        # if diff == 0x0101:
                            #     print(diffr)
                            
                        if len(diffrs)>len(set(diffrs))+2:
                            self.fixedtable = table
                            print("found!")
                            print("found!")

                            print("found!")

                            print("found!")

                            print("found!")

                            print("found!")
                            self.fixedtable = table
                            print("[+] Useful fault pattern found!")
                            with open("faulty_table.bin", "wb") as f:
                                f.write(table)

                            return True

                        # diffls.append(diffl)
                        # diffrs.append(diffr)

                    # if mark == 1:
                    #     self.fixedtable = table
                    #     print("[+] Useful fault pattern found!")
                    #     with open("faulty_table.bin", "wb") as f:
                    #         f.write(table)

                    #     return True

                self.logfile.write(log + '\n')
                self.logfile.flush()
                if count % 1000 == 0:
                    print(".", end="", flush=True)
                del table

        return False
    
    
    def run(self, lastroundkeys=[], encrypt=None):
        print("len of goldendata:"+str(len(self.goldendata)))
        if encrypt is not None and self.encrypt is not None:
            assert self.encrypt==encrypt
        if encrypt is not None and self.encrypt is None:
            self.encrypt=encrypt
        self.lastroundkeys=lastroundkeys
        if self.logfilename is None:
            self.logfile=open('%s_%s.log' % (self.targetbin, self.inittimestamp), 'w')
        else:
            self.logfile=open(self.logfilename, 'w')
        if self.addresses is None:
            print("len of goldendata:"+str(len(self.goldendata)))
            self.tabletree=deque(self.splitrange((0, len(self.goldendata))))

            # print(self.tabletree)
        elif type(self.addresses) is str:
            self.tabletree=deque()
            with open(self.addresses, 'r') as reflog:
                for line in reflog:
                    self.tabletree.extend([(int(line[9:19],16),int(line[20:30],16))])
        else:
            self.tabletree=deque(self.splitrange(self.addresses))
        self.processed_input=self.processinput(self.iblock, self.blocksize)
        # Prepare golden output
        starttime=time.time()
        
        oblock,status,diff=self.doit(self.goldendata, self.processed_input, protect=False, init=True) #SPECK
        # print(status)
        # Set timeout = N times normal execution time
        self.timeout=(time.time()-starttime)*self.timeoutfactor
        if oblock is None or status is not self.FaultStatus.NoFault:
            raise AssertionError('Error, could not obtain golden output, check your setup!')
        self.encpairs=[(self.iblock, oblock)]
        self.correctct = oblock
        # self.decpairs=[(self.iblock, oblock)]
        # self.encstatus=[0,0,0,0]
        # self.decstatus=[0,0,0,0]
        # print(len(self.encpairs))
        self.dig()
        
        if self.fixedtable is not None:
            i=0
            ii=899
            diffs = []
            correctcts = []
            faultycts = []
            flag = 0
            with open("record_file.txt","w") as f:
                while(i<10):
                    
                    oblockct,statusct,diffct=self.doit(self.goldendata, self.processed_input, protect=False,counter=ii) #SPECK
                    oblockft,statusft,diffft=self.doit(self.fixedtable, self.processed_input, protect=False,counter=ii) #SPECK
                    if oblockft == None or oblockct==None:
                        continue
                    diff = oblockct[0]^oblockct[1]^oblockft[0]^oblockft[1]
                    diffl = oblockct[0]^oblockct[1]
                    # diffs.append(diff)
                
                    if diff!=0:
                        # print("correct:"+str(oblockct))
                        # print("faulty:"+str(oblockft))
                        # print(diff)
                        print("in porcess----"+str(ii-899)+"-------:"+str(i))
                        f.write(f"correct:")
                        f.write(f"{oblockct}\n")
                        f.write(f"faulty:")
                        f.write(f"{oblockft}\n")
                        # f.write(f"diff:")
                        f.write(f"{diff}\n")
                        diffs.append(diff)
                        
                        self.correctcts.append(oblockct) 
                        self.faultycts.append(oblockft)
                        correctcts.append(oblockct) 
                        faultycts.append(oblockft)
                        if diffl==1:
                            i+=1
                            print("found"+str(i))
                    ii+=1
            
                # for q in range(i):
                    
                    # f.write(f"correct:")
                    # f.write(f"{correctcts[q]}\n")
                    # f.write(f"faulty:")
                    # f.write(f"{faultycts[q]}\n")
                    # # f.write(f"diff:")
                    # f.write(f"{diff[q]}\n")
                    
            group_from_aligned_lists(correctcts,faultycts,"text.txt")
        # tracefiles=self.savetraces()
        tracefiles=None
        os.remove(self.targetdata)
        self.logfile.close()
        return tracefiles,self.correctcts,self.faultycts,self.fixedtable
