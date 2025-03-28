import sys
import dogpool_dfa
import Pheonix_SPECK
import random 
def process_input(iblock, blocksize):
    p = '%0*x' % (2 * blocksize, iblock)  # 将 iblock 转为指定长度的十六进制字符串
    mid = len(p) // 2  # 找到中间位置，将字符串分成两半
    first_word = int(p[:mid], 16)  # 前半部分
    second_word = int(p[mid:], 16)  # 后半部分
    return (None, [first_word, second_word])
def process_output(output, blocksize):
    # 1. 解码bytes为字符串并去除首尾空白字符
    hex_str = output.decode('ascii').strip()
    
    # 2. 按空格分割字符串，得到两个十六进制子串
    hex_parts = hex_str.split()
    
    # 3. 将每个十六进制字符串转换为整数（带0x前缀）
    result = [int(part, 16) for part in hex_parts]
    
    return result
# def process_output(output, blocksize):
#     # 获取以 'OUTPUT' 开头的那一行，并提取后面的十六进制部分
#     print(type(output))
#     print(output)
#     hex_data=int(b''.join([x for x in output.split(b'\n') if x.find(b'OUTPUT')==0][0][10:].split(b' ')), blocksize)
#     # hex_data = b''.join([x for x in output.split(b'\n') if x.find(b'OUTPUT') == 0][0][10:].split(b' '))

#     # 将十六进制数据转换为整数
#     i = int(hex_data, 16)

#     # 计算中间位置，将数据分为两部分
#     hex_str = f'{i:0{2 * blocksize}x}'  # 按照指定的 blocksize 生成十六进制字符串
#     mid = len(hex_str) // 2  # 计算中间位置

#     # 分割为两个整数
#     first_word = int(hex_str[:mid], 16)
#     second_word = int(hex_str[mid:], 16)

#     return [first_word, second_word]
cct_set = []
fcts_set = []
diff_set = []
for i in range(1):
    engine=dogpool_dfa.Acquisition(targetbin='./white_box_arx', targetdata='./white_box_arx', goldendata='./white_box_arx.gold',
            dfa=Pheonix_SPECK,iblock=random.randint(0,255),depth_first_traversal=True, processinput=process_input, processoutput=process_output,faults=20, minfaultspercol=None)
    tracefiles_sets,cct,fcts=engine.run()
    # cct_set.append(cct)
    # fcts_set.append(fcts)
    # diffs=[]
    # for fct in fcts:
    #     # print(fct)
    #     diff0=cct[0]^fct[0]
    #     diff1=cct[1]^fct[1]
    #     diff=[]
    #     diff.append(diff0)
    #     diff.append(diff1)
    #     # print(diff)
    #     diffs.append(diff)
    
    
    








print("--------------")
print(cct)
print("--------------")

print(len(fcts))
# for tracefile in tracefiles_sets[0]:
#     print(tracefile)
    # if phoenixAES.crack_file(tracefile):
    #     break