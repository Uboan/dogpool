import ast
from z3 import *
from enum import Enum

import time
from numpy import power 

WORDSIZE =16
ALPHA = 7
BEITA = 2
KEYSIZE = 64
SPECKROUNDS = 22
MODMASK =2**WORDSIZE-1

blocksize = 2*WORDSIZE

FaultStatus = Enum('FaultStatus', 'Crash Loop NoFault MinorFault MajorFault WrongFault GoodEncFault GoodDecFault')

def RotRshift(x,s):
    return ((x>>s)|(x<<(WORDSIZE-s)))&MODMASK

def RotLshift(x,s):
    return ((x<<s)|(x>>(WORDSIZE-s)))&MODMASK

def RightShift_id(round,x,y,mark,model):
    
    z1 = BitVec(('x_' +mark+ str(round)+'_afterRightshift'),WORDSIZE)
    z2 = BitVec(('y_' +mark+ str(round)+'_afterRightshift'),WORDSIZE)
    model.add(z1==RotateRight(x,ALPHA)&MODMASK)
    model.add(z2==y)
    return z1,z2
    
def modular_add_id(round,x,y,mark,model):
    
    z1 = BitVec(('x_' +mark+ str(round)+'_afterMODADD'),WORDSIZE)
    z2 = BitVec(('y_' +mark+ str(round)+'_afterMODADD'),WORDSIZE)
    
    model.add(z1 ==( x+y)&MODMASK)
    model.add(z2 == y)
    return z1,z2

def AddRKEY_id(round,x,y,mark,rk,model):
    z1 = BitVec(('x_' +mark+ str(round)+'_afterAddRoundKey'),WORDSIZE)
    z2 = BitVec(('y_' +mark+ str(round)+'_afterAddRoundKey'),WORDSIZE)
    model.add(z1 == (x^rk))
    model.add(z2 == y)
    return z1,z2

def id_LeftShift(round,x,y,mark,model):
    z1 = BitVec(('x_' +mark+ str(round)+'_afterLeftshift'),WORDSIZE)
    z2 = BitVec(('y_' +mark+ str(round)+'_afterLeftshift'),WORDSIZE)
    model.add(z1==x)
    model.add(z2==RotateLeft(y,BEITA)&MODMASK)    
    return z1,z2        

def id_xor(round,x,y,mark,model):
    z1 = BitVec(('x_' +mark+ str(round)+'_afterxor'),WORDSIZE)
    z2 = BitVec(('y_' +mark+ str(round)+'_afterxor'),WORDSIZE)
    model.add(z1==x)
    model.add(z2==(x^y))
    return z1,z2

# // crypto warning 
def GenENRdES(x,y,mark,round,RoundKey,model):
    x_afterRS,y_afterRS = RightShift_id(round,x,y,mark,model)    
    x_afterMADD,y_afterMADD = modular_add_id(round,x_afterRS,y_afterRS,mark,model)
    x_afterARK,y_afterARK = AddRKEY_id(round,x_afterMADD,y_afterMADD,mark,RoundKey,model)
    x_afterLS,y_afterLS = id_LeftShift(round,x_afterARK,y_afterARK,mark,model)
    x_afterxor,y_afterxor = id_xor(round,x_afterLS,y_afterLS,mark,model)
    return x_afterxor,y_afterxor
    
def SpeckNormal_round(x,y,rk):
    # print('x : beforeAnything '+str(x))
    x = RotRshift(x,ALPHA)&MODMASK
    # print('x : afterRightS '+str(x))
    x = (x+y)&MODMASK
    # print('x : afterMODADD '+str(x))
    x = (x^rk)&MODMASK
    # print('x : afterARK '+str(x))
    y = RotLshift(y,BEITA)&MODMASK
    
    # print('y : afterLeftS '+str(y))
    y = (x^y)&MODMASK
    # print('y : afterXOR '+str(y))
    return x,y

def SpeckNormal_KEYEXPAND(MasterKey):
    rk = []
    rk.append(MasterKey[0])
    L = []
    m = (int)(KEYSIZE/WORDSIZE)
    for i in range(m-1):
        L.append(MasterKey[i+1])
        
    for i in range(SPECKROUNDS-1):
        Lround,rkround = SpeckNormal_round(L[i],rk[i],i)
        L.append(Lround)
        rk.append(rkround)
    return rk

def SpeckENC(x,y,rk):
    for i in range(SPECKROUNDS):
        
        x,y = SpeckNormal_round(x,y,rk[i])
    return int(x),int(y)

def SpeckNormal_Decround(x, y, k):
    xor_xy = x ^ y

    new_y = ((xor_xy << (WORDSIZE - BEITA)) + (xor_xy >> BEITA)) & MODMASK

    xor_xk = x ^ k

    msub = ((xor_xk - new_y) + MODMASK+1) % (MODMASK+1)

    new_x = ((msub >> (WORDSIZE - ALPHA)) + (msub << ALPHA)) & MODMASK

    return new_x, new_y

def SpeckDEC(x,y,rk):
    
    for i in range(SPECKROUNDS):
        
        x,y = SpeckNormal_Decround(x,y,rk[SPECKROUNDS-i-1])
    return int(x),int(y)

def SpeckFault_ENC(x,y,rk,faultmaskx,faultmasky,round):
    for i in range(round):
        x,y = SpeckNormal_round(x,y,rk[i])
        #print(x)
    x = faultmaskx^x
    y = faultmasky^y
    for i in range(round,SPECKROUNDS):
        x,y = SpeckNormal_round(x,y,rk[i])    
    return int(x),int(y)

import random

# MasterKey =[0x000102030908,0x010001020300,0x000010203d0c,0x08090a0b0504]# [0x00010203 ,0x08090a0b, 0x10111213]


def MAFA_real(N,M,correctCtxt,faultyCtxt,r=SPECKROUNDS-1):
    model = Solver()
    
    lastRK = BitVec(('lastRK' ),WORDSIZE)
    faultmsX = []
    timestart = time.time()
    for m in range(M):
        
        correctYR = correctCtxt[m][0][0]^correctCtxt[m][0][1]
        correctYR_1 = RotRshift(correctYR,BEITA)
        faultyYR = faultyCtxt[m][0][0]^faultyCtxt[m][0][1]
        faultyYR_1 = RotRshift(faultyYR,BEITA)
        faultMasky = (correctYR_1^faultyYR_1 )&MODMASK
        
        print("faultMasky"+str(faultMasky))
        faultmsx = BitVec(('faultmsX_'+str(m)),WORDSIZE)
        faultmsX.append(faultmsx)
        for i in range(0,N):

            xafterEN= BitVec(('xafterEN' + str(SPECKROUNDS-1)),WORDSIZE)
            yafterEN= BitVec(('yafterEN' + str(SPECKROUNDS-1)),WORDSIZE)
                            
            x1 = BitVec(('x'+str(m)+'_'+str(i)+'c_' + str(r)),WORDSIZE)
            y1 = BitVec(('y'+str(m)+'_'+str(i)+'c_' + str(r)),WORDSIZE) 
            
            xc = x1 
            yc = y1
            for rc in range(r,SPECKROUNDS):  
                if(rc==r):                 
                    xc = BitVec(('x'+str(m)+'_'+str(i)+'c_' + str(rc)),WORDSIZE)
                    yc = BitVec(('y'+str(m)+'_'+str(i)+'c_' + str(rc)),WORDSIZE)
                xafterEN,yafterEN = GenENRdES(xc,yc,str(m)+str(i)+'c',rc,lastRK,model) # // #2
                xc = BitVec(('x'+str(m)+'_'+str(i)+'c_' + str(rc+1)),WORDSIZE)
                yc = BitVec(('y'+str(m)+'_'+str(i)+'c_' + str(rc+1)),WORDSIZE)
                model.add(xc==xafterEN)
                model.add(yc==yafterEN)

            model.add((correctCtxt[m][i][0]) ==xafterEN)
            model.add(correctCtxt[m][i][1]==yafterEN)
            x2 = BitVec(('x'+str(m)+'_'+str(i)+'f_' + str(r)),WORDSIZE)
            y2 = BitVec(('y'+str(m)+'_'+str(i)+'f_' + str(r)),WORDSIZE)
            xf = x2 
            yf = y2
            for rc in range(r,SPECKROUNDS): 
                if(rc==r):                  
                                
                    xf = BitVec(('x'+str(m)+'_'+str(i)+'f_' + str(rc)),WORDSIZE)
                    yf = BitVec(('y'+str(m)+'_'+str(i)+'f_' + str(rc)),WORDSIZE)
                xafterEN,yafterEN = GenENRdES(xf,yf,str(m)+str(i)+'f',rc,lastRK,model) # // #2
                xf = BitVec(('x'+str(m)+'_'+str(i)+'f_' + str(rc+1)),WORDSIZE)
                yf = BitVec(('y'+str(m)+'_'+str(i)+'f_' + str(rc+1)),WORDSIZE)
                model.add(xf==xafterEN)
                model.add(yf==yafterEN)
            
            model.add(faultyCtxt[m][i][0]==xafterEN)
            model.add(faultyCtxt[m][i][1]==yafterEN)
            
            model.add(faultmsX[m]==(x1^x2))
            model.add(faultMasky==(y1^y2))  #// #4  assume that y is fixed, becuz the differential of y is known
            
            

    count = 0
    while model.check() == sat:
        count=count+1
        print("sat:")
        print (model.model()[lastRK])
        
        # print (bin(model.model()[lastRK]))
        model.add(lastRK!=model.model()[lastRK])
    print("the number of solution:"+str(count))
    timeend = time.time()
    if(count==0):
        print("unsat")
        return 1
    print("Attack time:%.2f"%(timeend-timestart))



def filter_by_xor_differential(cct, fct):
    filtered_cct_sets = []
    filtered_fct_sets = []
    differential_counts = []  # To store the number of instances in each differential group
    
    for cct_set, fct_set in zip(cct, fct):
        differential_map_cct = {}  # To store the cct pairs by their differential
        differential_map_fct = {}  # To store the fct pairs by their differential
        
        for cct_pair, fct_pair in zip(cct_set, fct_set):
            # Calculate the differential (c0_i ⊕ c1_i) ⊕ (f0_i ⊕ f1_i)
            xor_diff = (cct_pair[0] ^ cct_pair[1]) ^ (fct_pair[0] ^ fct_pair[1])

            # If the differential is not in the map, initialize the list for it
            if xor_diff not in differential_map_cct:
                differential_map_cct[xor_diff] = []
                differential_map_fct[xor_diff] = []

            # Append the pair to the corresponding differential group
            differential_map_cct[xor_diff].append(cct_pair)
            differential_map_fct[xor_diff].append(fct_pair)

        # After processing all pairs, record the filtered sets and their counts
        for diff in differential_map_cct:
            filtered_cct_sets.append(differential_map_cct[diff])
            filtered_fct_sets.append(differential_map_fct[diff])
            differential_counts.append(len(differential_map_cct[diff]))  # Count the number of instances

    # Combine filtered lists with counts and sort by count in descending order
    combined = list(zip(filtered_cct_sets, filtered_fct_sets, differential_counts))
    sorted_combined = sorted(combined, key=lambda x: x[2], reverse=True)

    # Unpack the sorted result
    sorted_filtered_cct, sorted_filtered_fct, sorted_counts = zip(*sorted_combined)

    return list(sorted_filtered_cct), list(sorted_filtered_fct), list(sorted_counts)

def read_ciphertexts_from_file(filename):
    with open(filename, 'r') as file:
        content = file.read()

    # Split the content into cct and fct sections
    cct_start = content.find('cct =')
    fct_start = content.find('fct =')

    if cct_start != -1 and fct_start != -1:
        cct_text = content[cct_start + len('cct = '): fct_start].strip()
        fct_text = content[fct_start + len('fct = '):].strip()

        # Convert the string representations of lists to actual lists
        cct = ast.literal_eval(cct_text)
        fct = ast.literal_eval(fct_text)

        return cct, fct
    else:
        raise ValueError("Could not find 'cct' or 'fct' sections in the file")

def key_recovery(filename):
    # Example usage
    
    # cct, fct = read_ciphertexts_from_file(filename)


    cct, fct = read_ciphertexts_from_file(filename)
    filtered_cct, filtered_fct, differential_counts = filter_by_xor_differential(cct, fct)
    MAFA_real(differential_counts[1],2,filtered_cct,filtered_fct)
    
    
# filename = "wb64_a.txt"
# key_recovery(filename)

# def check(output, encrypt=None, verbose=1, init=False, _intern={}):
def check(output, encrypt=None, verbose=1, init=False, _intern={}):
    """
    Checks an output against a reference.

    The first call to the function sets the internal reference as the given output
    :param output: potentially faulty output
    :param encrypt: True if encryption, False if decryption
    :param verbose: verbosity level, prints only if verbose>2
    :param init: if True, resets the internal reference as the given output
    :returns: a FaultStatus
    """
    if init:
        _intern.clear()

    if not _intern:
        _intern['goldenref']=output
        if verbose>2:
            print("FI: record golden ref")
        return FaultStatus.NoFault,None
    if output == _intern['goldenref']:
        if verbose>2:
            print("FI: no impact")
        return FaultStatus.NoFault,None
    diff=[]  
    # print("correct:"+str(_intern['goldenref'])) 
    # print("faulty:"+str(output) )
    
    # print(len(output))
    # print(len(_intern['goldenref']))
    faudiff = output[0]^output[1]
    cordiff = _intern['goldenref'][0]^_intern['goldenref'][1]
    # diff.append(output[0]^output[1])
    diff.append(output[0]^_intern['goldenref'][0])
    diff.append(cordiff^faudiff)
    # print("diff:"+str(diff))
    if diff[0]== diff[1] == 0:
        return FaultStatus.NoFault,None
    return FaultStatus.GoodEncFault,diff
