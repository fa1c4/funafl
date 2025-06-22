from copy import deepcopy
from bisect import bisect_right


'''
define Constants
'''
# comparison instructions
cmp_insn = [
    'jmp', 'test', 'jz', 'jnz', 'jc', 'jnc', 'je', 'jne',
    'js', 'jns', 'jo', 'jno', 'jp', 'jpe', 'jnp', 'jpo', 'ja',
    'jnbe', 'jae', 'jnb', 'jb', 'jane', 'jbe', 'jna', 'jg', 'jnle',
    'jge', 'jnl', 'jl', 'jnge', 'jle', 'jng',
    'cmp', 'cmpsb', 'cmpsw', 'cmpsd', 'cmpxchg'
]

# memory, file, string instructions
mem_insn = [
    'malloc', 'calloc', 'realloc', 'alloca', 'free', 'shmat',
    'fopen', 'fread', 'fputc', 'memcpy', 'memcmp',
    'read', 'write', 'memset', 'strtod', 'strtol', 'strtoul',
    'strcpy', 'strncpy', 'strcat', 'strncat', 'strlen'
]

# data instructions
data_insn = [
    'cmps', 'cmpsq', 'cmpsb', 'cmpsd', 'cmpsl', 'cmpsw',
    'lods', 'lodsq', 'lodsb', 'lodsl', 'lodsw',
    'movs', 'movsq', 'movsb', 'movsl', 'movsd',
    'smovl', 'movsw', 'smovw', 'scas', 'scasq', 'scasb',
    'scasl', 'scasd', 'scasw', 
    'stos', 'stosq', 'stosb', 'stosl', 'stosd', 'stosw',
    'rep', 'repe', 'repz', 'repne', 'repnz'
]


'''
parameters settings
'''
parameters = {
    'partition_wl_graph': 0.5, 
    'function_count_lower': 0.99, 
    'partition': 0.1, 
    'attributes_num': 7, 
    'wl_time_base': 1200,
    'update_interval_hours': 0.75
}


'''
define class of basic block
'''
class BBlock(object):
    '''
    basic block class
    '''
    def __init__(self, hash_val, func_name, func_name_hash, addr):
        self.hash_val = hash_val
        self.func_name = func_name
        self.func_name_hash = func_name_hash
        self.addr = addr
        self.cmp_num = 0
        self.string_num = 0
        self.imme = 0
        self.mem_num = 0
        self.ins_num = 0
        self.offspring = 0.0
        self.betweenness = 0.0
        self.hash_val_list = []
    
    def set_attr(self, cmp_num, mem_num, ins_num, string_num, imme, offspring, betweenness):
        '''
        set attributes of basic block
        '''
        self.cmp_num = cmp_num
        self.mem_num = mem_num
        self.ins_num = ins_num
        self.string_num = string_num
        self.imme = imme
        self.offspring = offspring
        self.betweenness = betweenness

    def set_attr_by_list(self, list_attr):
        '''
        set attributes of basic block by list
        [cmp_num, mem_num, ins_num, string_num, imme, offspring, betweenness]
        '''
        self.cmp_num = list_attr[0]
        self.mem_num = list_attr[1]
        self.ins_num = list_attr[2]
        self.string_num = list_attr[3]
        self.imme = list_attr[4]
        self.offspring = list_attr[5]
        self.betweenness = list_attr[6]

    def add_attr_by_list(self, list_attr):
        '''
        add attributes of basic block by list
        [cmp_num, mem_num, ins_num, string_num, imme, offspring, betweenness]
        '''
        self.cmp_num += list_attr[0]
        self.mem_num += list_attr[1]
        self.ins_num += list_attr[2]
        self.string_num += list_attr[3]
        self.imme += list_attr[4]
        self.offspring += list_attr[5]
        self.betweenness += list_attr[6]

    def get_attr(self):
        '''
        get attributes of basic block
        [cmp_num, mem_num, ins_num, string_num, imme, offspring, betweenness]
        '''
        return [self.cmp_num, self.mem_num, self.ins_num, self.string_num, self.imme, self.offspring, self.betweenness]

    def set_cmp_num(self, cmp_num):
        '''
        set cmp num of basic block
        '''
        self.cmp_num = cmp_num
    
    def incre_mem_num(self):
        '''
        increase mem num of basic block
        '''
        self.mem_num += 1

    def set_imme(self, imme):
        '''
        set immediate value of basic block
        '''
        self.imme = imme

    def set_offspring(self, offspring):
        '''
        set offspring of basic block
        '''
        self.offspring = offspring

    def set_betweenness(self, betweenness):
        '''
        set betweenness of basic block
        '''
        self.betweenness = betweenness


'''
define class for Basic Block
'''
class BBWrapper(object):
    def __init__(self, ea, bb):
        self.ea_ = ea
        self.bb_ = bb

    def get_bb(self):
        return self.bb_

    def __lt__(self, other):
        if not isinstance(other, BBWrapper):
            return NotImplemented
        return self.ea_ < other.ea_
    
    def __eq__(self, other):
        if not isinstance(other, BBWrapper):
            return NotImplemented
        return self.ea_ == other.ea_


'''
source code for data processing
'''
def function_name_hash(func_name):
    '''
    Function to hash the function name to a unique integer.
    '''
    seed = 0xfa1c4
    hash_val = 0
    for ch in func_name:
        hash_val = (hash_val * seed + ord(ch)) & 0x7FFFFFFF

    return hash_val


def list_square(lst):
    '''
    Function to square each element in a list.
    '''
    res = []
    for key in lst:
        res.append(key * key)

    return res


def list_add(lst1, lst2):
    '''
    Function to add two lists element-wise.
    '''
    if len(lst1) == 0:
        return deepcopy(lst2)
    elif len(lst2) == 0:
        return deepcopy(lst1)
    
    assert len(lst1) == len(lst2), "data_process.py: The two lists must have the same length."
    res = []
    for i in range(len(lst1)):
        res.append(lst1[i] + lst2[i])

    return res


def list_parameter_multiply(lst, multi):
    res = []
    for i in lst:
        res.append(i * multi)
    
    return res


def sum_of_lists(lists):
    '''
    Function to sum a list of lists element-wise.
    '''
    res = []
    if len(lists) == 0:
        return res
    
    for lst in lists:
        res = list_add(res, lst)
    
    return res


'''
define class of Binary Function
'''
class Binary_Function:
    def __init__(self, addr, name, hash_val):
        super(Binary_Function, self).__init__()
        self.addr = addr
        self.name = name
        self.hash_val = hash_val
        self.cmp_num = 0
        self.mem_num = 0
        self.ins_num = 0
        self.bb_num = 0
        self.offspring_reciprocal = 0
        self.betweeness = 0
        self.retain1 = 0
        self.retain2 = 0
        self.retain3 = 0

    def set_attr(self, cmp_num, mem_num, ins_num, bb_num, offspring_reciprocal, betweeness, retain1, retain2, retain3):
        self.cmp_num = cmp_num
        self.mem_num = mem_num
        self.ins_num = ins_num
        self.bb_num = bb_num
        self.offspring_reciprocal = offspring_reciprocal
        self.betweeness = betweeness
        self.retain1 = retain1
        self.retain2 = retain2
        self.retain3 = retain3

    def set_attr_by_list(self, list_addr):
        self.cmp_num = list_addr[0]
        self.mem_num = list_addr[1]
        self.ins_num = list_addr[2]
        self.bb_num = list_addr[3]
        self.offspring_reciprocal = list_addr[4]
        self.betweeness = list_addr[5]
        self.retain1 = list_addr[6]
        self.retain2 = list_addr[7]
        self.retain3 = list_addr[8]
    
    def get_attr(self):
        return [
            self.cmp_num, 
            self.mem_num, 
            self.ins_num, 
            self.bb_num, 
            self.offspring_reciprocal, 
            self.betweeness, 
            self.retain1, 
            self.retain2, 
            self.retain3
        ]

    def set_cmp_num(self, cmp_num):
        self.cmp_num = cmp_num
    
    def get_cmp_num(self):
        return self.cmp_num

    def increase_mem_num(self):
        self.mem_num += 1
    
    def set_mem_num(self, mem_num):
        self.mem_num = mem_num
    
    def set_ins_num(self, ins_num):
        self.ins_num = ins_num

    def get_ins_num(self):
        return self.ins_num
    
    def set_bb_num(self, bb_num):
        self.bb_num = bb_num
    
    def get_bb_num(self):
        return self.bb_num
    
    def set_offspring_reciprocal(self, offspring_reciprocal):
        self.offspring_reciprocal = offspring_reciprocal
    
    def get_offspring_reciprocal(self):
        return self.offspring_reciprocal
    
    def set_betweeness(self, betweeness):
        self.betweeness = betweeness
    
    def get_betweeness(self):
        return self.betweeness

    def set_retain1(self, retain1):
        self.retain1 = retain1
    
    def get_retain1(self):
        return self.retain1
    
    def set_retain2(self, retain2):
        self.retain2 = retain2

    def get_retain2(self):
        return self.retain2
    
    def set_retain3(self, retain3):
        self.retain3 = retain3
    
    def get_retain3(self):
        return self.retain3
