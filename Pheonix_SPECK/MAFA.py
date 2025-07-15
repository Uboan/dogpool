from z3 import *
  
import time
from numpy import power 

WORDSIZE =16
ALPHA = 7
BEITA = 2
KEYSIZE = 64
SPECKROUNDS = 22
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





def MFDDFA(N,M,correctCtxt,faultyCtxt,r=SPECKROUNDS-1):# multi-fixed difference fault analysis  
                                                        # where M is the number of different fixed fault
                                                        # where N is the number of ciphertexts pairs for each fixed fault
                                                        # correctCtxt and faultyCtxt are correct and faulty ciphertexts set (3-dim list)          
                                                        # r is the number of targeted round
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
    
 


cct =[[
[36476, 63213],#diff in the left: 0x3e8e
[29733, 60686],#diff in the left: 0x3e2a
[43505, 24567],#diff in the left: 0x7e46
[52874, 46874],#diff in the left: 0x3d8e
[47342, 58347],#diff in the left: 0x7e4a
[3076, 22631],#diff in the left: 0x3b86

]]

fct =[[
[45298, 48515],
[18959, 42692],
[55223, 21585],
[62212, 65396],
[50852, 59457],
[14210, 5633],
]]
MFDDFA(len(cct[0]),1,cct,fct,SPECKROUNDS-1)
