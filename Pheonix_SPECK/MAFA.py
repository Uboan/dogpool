from z3 import *
  
import time
from numpy import power 

WORDSIZE =32
ALPHA = 8
BEITA = 3
KEYSIZE = 64
SPECKROUNDS = 27
MODMASK =2**WORDSIZE-1

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

MasterKey =[0x000102030908,0x010001020300,0x000010203d0c,0x08090a0b0504]# [0x00010203 ,0x08090a0b, 0x10111213]

# faultMasky = 0x1233

def MAFAtest(N,r,M,faultMaskx,faultMasky):
    model = Solver()
    plntxt1 = []
    plntxt2 = []
    cpytxt1 = []
    cpytxt2 = []
    RK = SpeckNormal_KEYEXPAND(MasterKey) #   // #1
    print("RoundKey:")
    timestart = time.time()
    # for rr in RK:
    #     print(rr)
    # L,K = GenKSRdESALL(model,SPECKROUNDS)
    lastRK = BitVec(('lastRK_' + str(0)),WORDSIZE)
    faultmsX = []
    for m in range(M):
        faultMaskx = faultMaskx^(random.randint(0,MODMASK))
        faultMasky = faultMasky^(random.randint(0,MODMASK))
        # faultMaskx = faultMaskx^MODMASK
        # faultMasky = faultMasky^MODMASK
        # print("FaultMask X: "+str(hex(faultMaskx)))
        # print("FaultMask Y: "+str(hex(faultMasky)))
        faultmsx = BitVec(('faultmsX_'+str(m)),WORDSIZE)
        faultmsX.append(faultmsx)
        # faultmsY =  BitVec(('faultmsY'),WORDSIZE)
        for i in range(m*N,(m+1)*N):
            plntxt1.append(random.randint(0,MODMASK))
            plntxt2.append(random.randint(0,MODMASK))
            ciphertext1,ciphertext2 = SpeckENC(plntxt1[i],plntxt2[i],RK)
            # dectxt1,dectxt2 = SpeckDEC(ciphertext1,ciphertext2,RK)
            # if dectxt1!=plntxt1[i] and dectxt2!=plntxt2[i]:
            #     print("WRONG shit!!!!")
            #     return 
            # print(ciphertext1)
            cpytxt1.append(ciphertext1) 
            cpytxt2.append(ciphertext2)
            xafterEN= BitVec(('xafterEN' + str(SPECKROUNDS-1)),WORDSIZE)
            yafterEN= BitVec(('yafterEN' + str(SPECKROUNDS-1)),WORDSIZE)
                            
            x1 = BitVec(('x'+str(i)+'c_' + str(r)),WORDSIZE)
            y1 = BitVec(('y'+str(i)+'c_' + str(r)),WORDSIZE) 
            
            xc = x1 
            yc = y1
            for rc in range(r,SPECKROUNDS):  
                if(rc==r):                 
                    xc = BitVec(('x'+str(i)+'c_' + str(rc)),WORDSIZE)
                    yc = BitVec(('y'+str(i)+'c_' + str(rc)),WORDSIZE)
                xafterEN,yafterEN = GenENRdES(xc,yc,str(i)+'c',rc,lastRK,model) # // #2
                xc = BitVec(('x'+str(i)+'c_' + str(rc+1)),WORDSIZE)
                yc = BitVec(('y'+str(i)+'c_' + str(rc+1)),WORDSIZE)
                model.add(xc==xafterEN)
                model.add(yc==yafterEN)

            model.add((ciphertext1) ==xafterEN)
            model.add(cpytxt2[i]==yafterEN)
            x2 = BitVec(('x'+str(i)+'f_' + str(r)),WORDSIZE)
            y2 = BitVec(('y'+str(i)+'f_' + str(r)),WORDSIZE)
            xf = x2 
            yf = y2
            for rc in range(r,SPECKROUNDS): 
                if(rc==r):                  
                                
                    xf = BitVec(('x'+str(i)+'f_' + str(rc)),WORDSIZE)
                    yf = BitVec(('y'+str(i)+'f_' + str(rc)),WORDSIZE)
                xafterEN,yafterEN = GenENRdES(xf,yf,str(i)+'f',rc,lastRK,model) # // #2
                xf = BitVec(('x'+str(i)+'f_' + str(rc+1)),WORDSIZE)
                yf = BitVec(('y'+str(i)+'f_' + str(rc+1)),WORDSIZE)
                model.add(xf==xafterEN)
                model.add(yf==yafterEN)
            ciphertext1,ciphertext2 = SpeckFault_ENC(plntxt1[i],plntxt2[i],RK,faultMaskx,faultMasky,r)
            
            model.add(ciphertext1==xafterEN)
            model.add(ciphertext2==yafterEN)
            
            model.add(faultmsX[m]==(x1^x2))
            model.add(faultMasky==(y1^y2))  #// #4  assume that y is fixed, becuz the differential of y is known
            
            

    count = 0
    while model.check() == sat:
        count=count+1
        print("sat:")
        print (model.model()[lastRK])
        model.add(lastRK!=model.model()[lastRK])
    print("the number of solution:"+str(count))
    timeend = time.time()
    if(count==0):
        print("unsat")
        return 1
    print("Attack time:%.2f"%(timeend-timestart))

    
def CCT_MAFAtest(N,M,faultMaskx,faultMasky,r=SPECKROUNDS-1):
    model = Solver()
    plntxt1 = []
    plntxt2 = []
    cpytxt1 = []
    cpytxt2 = []
    RK = SpeckNormal_KEYEXPAND(MasterKey) #   // #1
    print("RoundKey:")
    timestart = time.time()
    for rr in RK:
        print(rr)
    # L,K = GenKSRdESALL(model,SPECKROUNDS)
    lastRK = BitVec(('lastRK_' + str(0)),WORDSIZE)
    faultmsX = []
    for m in range(M):
        faultMaskx = 32310# faultMaskx^(random.randint(0,MODMASK))
        faultMasky = 62438#faultMasky^(random.randint(0,MODMASK))
        # faultMaskx = faultMaskx^MODMASK
        # faultMasky = faultMasky^MODMASK
        # print("FaultMask X: "+str((faultMaskx)))
        # print("FaultMask Y: "+str((faultMasky)))
        faultmsx = BitVec(('faultmsX_'+str(m)),WORDSIZE)
        faultmsX.append(faultmsx)
        # faultmsY =  BitVec(('faultmsY'),WORDSIZE)
        for i in range(m*N,(m+1)*N):
            orcct1 = random.randint(0,MODMASK)
            orcct2 = random.randint(0,MODMASK)#orcct1^MODMASK
            dectxt1,dectxt2 = SpeckDEC(orcct1,orcct2,RK)
            
            plntxt1.append(dectxt1)
            plntxt2.append(dectxt2)
            ciphertext1,ciphertext2 = SpeckENC(plntxt1[i],plntxt2[i],RK)
            # dectxt1,dectxt2 = SpeckDEC(ciphertext1,ciphertext2,RK)
            # if dectxt1!=plntxt1[i] and dectxt2!=plntxt2[i]:
            #     print("WRONG shit!!!!")
            #     return 
            # print(ciphertext1)
            cpytxt1.append(ciphertext1) 
            cpytxt2.append(ciphertext2)
            xafterEN= BitVec(('xafterEN' + str(SPECKROUNDS-1)),WORDSIZE)
            yafterEN= BitVec(('yafterEN' + str(SPECKROUNDS-1)),WORDSIZE)
                            
            x1 = BitVec(('x'+str(i)+'c_' + str(r)),WORDSIZE)
            y1 = BitVec(('y'+str(i)+'c_' + str(r)),WORDSIZE) 
            
            xc = x1 
            yc = y1
            for rc in range(r,SPECKROUNDS):  
                if(rc==r):                 
                    xc = BitVec(('x'+str(i)+'c_' + str(rc)),WORDSIZE)
                    yc = BitVec(('y'+str(i)+'c_' + str(rc)),WORDSIZE)
                xafterEN,yafterEN = GenENRdES(xc,yc,str(i)+'c',rc,lastRK,model) # // #2
                xc = BitVec(('x'+str(i)+'c_' + str(rc+1)),WORDSIZE)
                yc = BitVec(('y'+str(i)+'c_' + str(rc+1)),WORDSIZE)
                model.add(xc==xafterEN)
                model.add(yc==yafterEN)

            model.add((ciphertext1) ==xafterEN)
            model.add(cpytxt2[i]==yafterEN)
            x2 = BitVec(('x'+str(i)+'f_' + str(r)),WORDSIZE)
            y2 = BitVec(('y'+str(i)+'f_' + str(r)),WORDSIZE)
            xf = x2 
            yf = y2
            for rc in range(r,SPECKROUNDS):  
                if(rc==r):                  
                                
                    xf = BitVec(('x'+str(i)+'f_' + str(rc)),WORDSIZE)
                    yf = BitVec(('y'+str(i)+'f_' + str(rc)),WORDSIZE)
                xafterEN,yafterEN = GenENRdES(xf,yf,str(i)+'f',rc,lastRK,model) # // #2
                xf = BitVec(('x'+str(i)+'f_' + str(rc+1)),WORDSIZE)
                yf = BitVec(('y'+str(i)+'f_' + str(rc+1)),WORDSIZE)
                model.add(xf==xafterEN)
                model.add(yf==yafterEN)
            ciphertext1,ciphertext2 = SpeckFault_ENC(plntxt1[i],plntxt2[i],RK,faultMaskx,faultMasky,r)
            
            model.add(ciphertext1==xafterEN)
            model.add(ciphertext2==yafterEN)
            
            model.add(faultMaskx==(x1^x2))
            model.add(faultMasky==(y1^y2))  #// #4  assume that y is fixed, becuz the differential of y is known
            
            

    count = 0
    while model.check() == sat:
        count=count+1
        print("sat:")
        print (model.model()[lastRK])
        # print(model.model()[faultmsX[0]])
        # print (model.model()[faultmsx])
        
        model.add(lastRK!=model.model()[lastRK])
        # model.add(faultmsX[0]!=model.model()[faultmsX[0]])
    print("the number of solution:"+str(count))
    timeend = time.time()
    if(count==0):
        print("unsat")
        return 1
    print("Attack time:%.2f"%(timeend-timestart))

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

        
# MAFAtest(3,SPECKROUNDS-1,2,2,3)        
        
# cct = [[[0xba17,0xa504],[0x94df,0x12f9],
#         [0x4644,0xd76b],[0x9914,0xca9d],[0x4537,0xf73d]], 
       
             
#        [[0x4ecb,0x70ce],[0x2fc5,0xa65e],
#         [0xfeca,0x21f],[0xd255,0xe0e9],[0x431b,0x4e8f]]       
#        ]
# fct = [[[0x48d1,0x585c],[0xb519,0x3ca1],
#         [0x7df0,0xe341],[0x25dc,0x79cb],[0xa835,0x15a1]],
       
       
#         [[0x6ce3,0xb301],[0x7add,0x12a1],
#          [0x7c40,0x6172],[0x4e9d,0x9dc6],[0xdcb3,0x30c0]]
# #         ]
# cct =[[[0xeecef37f,0x180227fa],
# [0x475e38e2,0x76904a29],
# [0xbbe76aea,0x2978adfe],
# [0xeecef37f,0x180227fa],
# [0x32e70110,0x326e7cbf],
# [0x475e38e2,0x76904a29],
# [0xd7a313bf,0x673346d8]
# ],[[0xeecef37f,0x180227fa],
# [0x475e38e2,0x76904a29],
# [0x6df3bb17,0x43c7b460],
# [0xd7a313bf,0x673346d8],
# [0xeecef37f,0x180227fa],
# [0xd880f5ec,0xd181c63c],
# [0x6df3bb17,0x43c7b460]
# ]]
# fct = [[[0x1e759914,0x96f13d18],
# [0x68413e95,0x27c73cd7],
# [0x95fe54d3,0x7929e34e],
# [0x1e759914,0x96f13d18],
# [0x3cfa672b,0x423b6a0d],
# [0x68413e95,0x27c73cd7],
# [0xf9245944,0x37fc7caa]
# ],[[0x1117e8dc,0xd73f65a],
# [0xba5fd6cf,0x61396e07],
# [0x8eeabd70,0x4a767804],
# [0x2aba495c,0x7082d638],
# [0x1117e8dc,0xd73f65a],
# [0x2207a203,0xc1ae5bd0],
# [0x8eeabd70,0x4a767804]
# ]]
# # MAFA_real(7,SPECKROUNDS-1,2,cct,fct)
# # m=0
# CCT_MAFAtest(1000,SPECKROUNDS-1,1,0x4a,0xc1)
# MAFAtest(4,SPECKROUNDS-1,3,0x4a,0xc1)
# print(hex(28004))
# print(hex(60772))