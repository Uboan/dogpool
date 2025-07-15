import sys
import dogpool_dfa
import catpool_dfa
import Pheonix_SPECK
import random 
def process_input(iblock, blocksize):
    p = '%0*x' % (2 * blocksize, iblock) 
    mid = len(p) // 2  
    first_word = int(p[:mid], 16)  
    second_word = int(p[mid:], 16)  
    return (None, [first_word, second_word])
def process_output(output, blocksize):
    hex_str = output.decode('ascii').strip()
    
    hex_parts = hex_str.split()
    
    result = [int(part, 16) for part in hex_parts]
    
    return result

cct_set = []
fcts_set = []
diff_set = []

# using catpool is to inject fault from top address to bottom
for i in range(1):
    engine=catpool_dfa.Acquisition(targetbin='./white_box_arx', targetdata='./white_box_arx', goldendata='./white_box_arx.gold',#[0x1bae8c,0x1d1000]
            dfa=Pheonix_SPECK,iblock=random.randint(0,255),depth_first_traversal=False, processinput=process_input, processoutput=process_output,minleafnail=1,faults=1,addresses=[0x2121a,0x22ec2], minfaultspercol=None)
    
    tracefiles_sets,cct,fcts,table=engine.run()
    cct_set.append(cct)
    fcts_set.append(fcts)     #,addresses=[0x1a21f6, 0x1d17c8]
    diffs=[]
    if table is not None:
        print("found!")
        
        
# using dogpool is to inject fault similar to deadpool 
# for i in range(1):
#     engine=dogpool_dfa.Acquisition(targetbin='./white_box_arx', targetdata='./white_box_arx', goldendata='./white_box_arx_2dot5t5',#[0x1bae8c,0x1d1000],addresses=[0x2121a,0x22ec2],[0x3000,0x3d2d2]
#             dfa=Pheonix_SPECK,iblock=random.randint(0,255),depth_first_traversal=True, processinput=process_input, processoutput=process_output,addresses=[0x20e86,0x22a27],minleafnail=1,faults=1, minfaultspercol=None)
#     tracefiles_sets,cct,fcts,table=engine.run()
#     cct_set.append(cct)
#     fcts_set.append(fcts)     #,addresses=[0x1a21f6, 0x1d17c8]
#     diffs=[]
#     if table is not None:
#         print("found!")
