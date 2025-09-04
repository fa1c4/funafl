'''
utils for static analysis
'''
from copy import deepcopy
from bisect import bisect_right
import hashlib
import struct
from typing import Optional, Union
import logging

import idc
import idaapi
import idautils

# Configure logging
logging.basicConfig(
    filename='acg_analysis_errors.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
)

'''
Define Constants
'''
FUNC_HIT_SHM_SIZE = 65536

mem_insn_functions = [
    # Memory allocation/management functions (for call instruction analysis)
    'malloc', 'calloc', 'realloc', 'alloca', 'free',
    
    # File operations functions
    'fopen', 'fread', 'fwrite', 'fclose', 'read', 'write',
    'fgets', 'fputs', 'fgetc', 'fputc',
    
    # Memory operations functions
    'memcpy', 'memcmp', 'memset', 'memmove', 'memchr',
    'strcpy', 'strncpy', 'strcat', 'strncat', 'strlen', 'strcmp', 'strncmp',
]

# Direct memory instructions (comprehensive list)
direct_memory_insns = {
    # Basic load/store
    'movsx', 'movzx', 'movsxd', 'movbe',
    'lea',  # Load effective address
    
    # Stack operations
    'push', 'pop', 'pusha', 'popa', 'pushad', 'popad',
    'pushf', 'popf', 'pushfd', 'popfd',
    'enter', 'leave',
    
    # String/memory operations
    'movs', 'movsb', 'movsw', 'movsd', 'movsq',
    'stos', 'stosb', 'stosw', 'stosd', 'stosq',
    'lods', 'lodsb', 'lodsw', 'lodsd', 'lodsq',
    'scas', 'scasb', 'scasw', 'scasd', 'scasq',
    'cmps', 'cmpsb', 'cmpsw', 'cmpsd', 'cmpsq',
    
    # Memory comparison and operations
    'cmpxchg', 'cmpxchg8b', 'cmpxchg16b',
    'xchg', 'xadd',
    'bound', 'xlat',
    
    # Segment loads
    'lds', 'les', 'lfs', 'lgs', 'lss',
    
    # FPU memory operations
    'fld', 'fst', 'fstp', 'fild', 'fist', 'fistp',
    'fbld', 'fbstp',
    
    # SSE/AVX memory operations
    'movss', 'movsd', 'movps', 'movpd', 'movaps', 'movapd',
    'movups', 'movupd', 'movhps', 'movhpd', 'movlps', 'movlpd',
    'movdqa', 'movdqu', 'movq', 'movd',
}


def is_arithmetic_operation(addr, mnemonic):
    '''
    Enhanced arithmetic operation detection with comprehensive instruction coverage
    Returns True if the instruction performs arithmetic computation
    '''
    try:
        # Comprehensive arithmetic instruction sets
        
        # Basic integer arithmetic
        basic_arith = {
            'add', 'adc', 'sub', 'sbb', 'mul', 'imul', 'div', 'idiv',
            'inc', 'dec', 'neg', 'abs'
        }
        
        # Comparison and test operations (arithmetic in nature)
        comparison_ops = {
            'cmp', 'test', 'cmpxchg', 'cmpxchg8b', 'cmpxchg16b'
        }
        
        # Bit manipulation and logical operations
        bit_logical = {
            'and', 'or', 'xor', 'not',
            'bt', 'btc', 'btr', 'bts',  # bit test operations
            'bsf', 'bsr',  # bit scan
            'popcnt', 'lzcnt', 'tzcnt',  # bit counting (modern CPUs)
            'andn',  # BMI instruction
        }
        
        # Shift and rotate operations
        shift_rotate = {
            'shl', 'shr', 'sal', 'sar', 'rol', 'ror', 'rcl', 'rcr',
            'shld', 'shrd',
            'shrx', 'shlx', 'sarx',  # BMI2 instructions
        }
        
        # x87 floating-point arithmetic
        x87_arith = {
            'fadd', 'faddp', 'fiadd', 'fsub', 'fsubp', 'fisub', 
            'fsubr', 'fsubrp', 'fisubr', 'fmul', 'fmulp', 'fimul', 
            'fdiv', 'fdivp', 'fidiv', 'fdivr', 'fdivrp', 'fidivr',
            'fabs', 'fchs', 'fsqrt', 'fsin', 'fcos', 'fsincos',
            'fptan', 'fpatan', 'f2xm1', 'fyl2x', 'fyl2xp1',
            'fscale', 'frndint', 'fxtract', 'fprem', 'fprem1',
            'fcom', 'fcomp', 'fcompp', 'ficom', 'ficomp',  # FP comparisons
            'ftst', 'fxam'  # FP tests
        }
        
        # SSE/SSE2 scalar floating-point arithmetic
        sse_scalar = {
            'addss', 'addsd', 'subss', 'subsd', 'mulss', 'mulsd', 
            'divss', 'divsd', 'sqrtss', 'sqrtsd', 'rsqrtss', 'rcpss',
            'minss', 'minsd', 'maxss', 'maxsd',
            'comiss', 'comisd', 'ucomiss', 'ucomisd',  # scalar comparisons
        }
        
        # SSE/SSE2 packed floating-point arithmetic
        sse_packed_fp = {
            'addps', 'addpd', 'subps', 'subpd', 'mulps', 'mulpd', 
            'divps', 'divpd', 'sqrtps', 'sqrtpd', 'rsqrtps', 'rcpps',
            'minps', 'minpd', 'maxps', 'maxpd',
            'cmpps', 'cmppd',  # packed comparisons
            'dpps', 'dppd',  # dot products (SSE4.1)
        }
        
        # SSE/SSE2/SSE4 packed integer arithmetic
        sse_packed_int = {
            # Packed addition
            'paddb', 'paddw', 'paddd', 'paddq', 'paddsb', 'paddsw', 'paddusb', 'paddusw',
            # Packed subtraction  
            'psubb', 'psubw', 'psubd', 'psubq', 'psubsb', 'psubsw', 'psubusb', 'psubusw',
            # Packed multiplication
            'pmullw', 'pmulhw', 'pmulhuw', 'pmulld', 'pmuludq', 'pmuldq',
            # Packed comparison
            'pcmpeqb', 'pcmpeqw', 'pcmpeqd', 'pcmpeqq',
            'pcmpgtb', 'pcmpgtw', 'pcmpgtd', 'pcmpgtq',
            # Packed min/max
            'pmaxsb', 'pmaxsw', 'pmaxsd', 'pmaxub', 'pmaxuw', 'pmaxud',
            'pminsb', 'pminsw', 'pminsd', 'pminub', 'pminuw', 'pminud',
            # Packed absolute value and difference
            'pabsb', 'pabsw', 'pabsd', 'psadbw',
            # Packed average
            'pavgb', 'pavgw',
        }
        
        # AVX arithmetic (256-bit versions of SSE and new operations)
        avx_arith = {
            # AVX floating-point arithmetic
            'vaddss', 'vaddsd', 'vaddps', 'vaddpd', 'vsubss', 'vsubsd', 'vsubps', 'vsubpd',
            'vmulss', 'vmulsd', 'vmulps', 'vmulpd', 'vdivss', 'vdivsd', 'vdivps', 'vdivpd',
            'vsqrtss', 'vsqrtsd', 'vsqrtps', 'vsqrtpd', 'vrsqrtss', 'vrsqrtps', 'vrcpss', 'vrcpps',
            'vminss', 'vminsd', 'vminps', 'vminpd', 'vmaxss', 'vmaxsd', 'vmaxps', 'vmaxpd',
            'vcmpss', 'vcmpsd', 'vcmppd', 'vcmpps',
            # AVX integer arithmetic  
            'vpaddb', 'vpaddw', 'vpaddd', 'vpaddq', 'vpaddsb', 'vpaddsw', 'vpaddusb', 'vpaddusw',
            'vpsubb', 'vpsubw', 'vpsubd', 'vpsubq', 'vpsubsb', 'vpsubsw', 'vpsubusb', 'vpsubusw',
            'vpmullw', 'vpmulhw', 'vpmulhuw', 'vpmulld', 'vpmuludq', 'vpmuldq',
            'vpcmpeqb', 'vpcmpeqw', 'vpcmpeqd', 'vpcmpeqq',
            'vpcmpgtb', 'vpcmpgtw', 'vpcmpgtd', 'vpcmpgtq',
        }
        
        # FMA (Fused Multiply-Add) instructions
        fma_ops = {
            'vfmadd132ps', 'vfmadd132pd', 'vfmadd132ss', 'vfmadd132sd',
            'vfmadd213ps', 'vfmadd213pd', 'vfmadd213ss', 'vfmadd213sd',
            'vfmadd231ps', 'vfmadd231pd', 'vfmadd231ss', 'vfmadd231sd',
            'vfmsub132ps', 'vfmsub132pd', 'vfmsub132ss', 'vfmsub132sd',
            'vfmsub213ps', 'vfmsub213pd', 'vfmsub213ss', 'vfmsub213sd',
            'vfmsub231ps', 'vfmsub231pd', 'vfmsub231ss', 'vfmsub231sd',
            'vfnmadd132ps', 'vfnmadd132pd', 'vfnmadd132ss', 'vfnmadd132sd',
            'vfnmadd213ps', 'vfnmadd213pd', 'vfnmadd213ss', 'vfnmadd213sd',
            'vfnmadd231ps', 'vfnmadd231pd', 'vfnmadd231ss', 'vfnmadd231sd',
            'vfnmsub132ps', 'vfnmsub132pd', 'vfnmsub132ss', 'vfnmsub132sd',
            'vfnmsub213ps', 'vfnmsub213pd', 'vfnmsub213ss', 'vfnmsub213sd',
            'vfnmsub231ps', 'vfnmsub231pd', 'vfnmsub231ss', 'vfnmsub231sd',
        }
        
        # Conditional moves (can be considered arithmetic in some contexts)
        conditional_arith = {
            'cmovo', 'cmovno', 'cmovb', 'cmovc', 'cmovnae', 'cmovnb', 'cmovnc', 'cmovae',
            'cmove', 'cmovz', 'cmovne', 'cmovnz', 'cmovbe', 'cmovna', 'cmova', 'cmovnbe',
            'cmovs', 'cmovns', 'cmovp', 'cmovpe', 'cmovnp', 'cmovpo',
            'cmovl', 'cmovnge', 'cmovge', 'cmovnl', 'cmovle', 'cmovng', 'cmovg', 'cmovnle'
        }
        
        # Combine all arithmetic instruction sets
        all_arithmetic_ops = (basic_arith | comparison_ops | bit_logical | shift_rotate | 
                             x87_arith | sse_scalar | sse_packed_fp | sse_packed_int | 
                             avx_arith | fma_ops | conditional_arith)
        
        # Check if instruction is arithmetic
        if mnemonic in all_arithmetic_ops:
            return True
        
        # Special cases for LEA instruction (can be used for arithmetic)
        if mnemonic == 'lea':
            # LEA can be used for arithmetic calculations like lea eax, [ebx + ecx*2 + 5]
            # We can check if it's being used for address calculation vs arithmetic
            # For now, we'll be conservative and not count LEA as arithmetic
            # since it's primarily an address calculation instruction
            return False
        
        # Additional pattern matching for prefixed instructions
        if mnemonic.startswith('rep'):
            # Handle repeated arithmetic operations
            base_mnemonic = mnemonic[3:].lstrip()  # Remove 'rep' prefix
            return base_mnemonic in all_arithmetic_ops
        
        return False
        
    except Exception as e:
        logging.warning(f"Error checking arithmetic operation at {hex(addr)}: {e}")
        return False


'''
Parameters settings
'''
ATTRS = ["imme_num", "string_num", "mem_num", "arith_num", "indegree", "offspring", "betweenness"]
attributes_num = len(ATTRS)
parameters = {
    'partition_wl_graph': 0.5,
    'function_count_lower': 0.99,
    'partition': 0.1,
    'attributes_num': attributes_num,
    'wl_time_base': 1200
}


class BBlock(object):
    '''
    Basic block class with standardized attributes order:
    [imme_num, string_num, mem_num, arith_num, indegree, offspring, betweenness]
    '''
    def __init__(self, hash_val, func_name, func_name_hash, addr):
        self.hash_val = hash_val
        self.func_name = func_name
        self.func_name_hash = func_name_hash
        self.addr = addr
        
        # Attributes in the specified order
        self.imme_num = 0      # Numeric constants count
        self.string_num = 0    # String constants count
        self.mem_num = 0       # Memory operation instructions count
        self.arith_num = 0     # Arithmetic operations count
        self.indegree = 0      # Incoming control flow edges count
        self.offspring = 0.0   # Basic block descendants
        self.betweenness = 0.0 # Betweenness centrality
        
        # Additional fields
        self.ins_num = 0       # Total instruction count
        self.hash_val_list = []
        self.string_refs = []  # Store string addresses for analysis
        self.constant_details = {'numeric': [], 'string': []}  # Store actual constants
    
    def set_attr(self, imme_num, string_num, mem_num, arith_num, indegree, offspring, betweenness):
        '''
        Set attributes of basic block in the specified order
        '''
        self.imme_num = imme_num
        self.string_num = string_num
        self.mem_num = mem_num
        self.arith_num = arith_num
        self.indegree = indegree
        self.offspring = offspring
        self.betweenness = betweenness

    def set_attr_by_list(self, list_attr):
        '''
        Set attributes by list: [imme_num, string_num, mem_num, arith_num, indegree, offspring, betweenness]
        '''
        if len(list_attr) >= 7:
            self.imme_num = list_attr[0]
            self.string_num = list_attr[1]
            self.mem_num = list_attr[2]
            self.arith_num = list_attr[3]
            self.indegree = list_attr[4]
            self.offspring = list_attr[5]
            self.betweenness = list_attr[6]

    def add_attr_by_list(self, list_attr):
        '''
        Add attributes by list: [imme_num, string_num, mem_num, arith_num, indegree, offspring, betweenness]
        '''
        if len(list_attr) >= 7:
            self.imme_num += list_attr[0]
            self.string_num += list_attr[1]
            self.mem_num += list_attr[2]
            self.arith_num += list_attr[3]
            self.indegree += list_attr[4]
            self.offspring += list_attr[5]
            self.betweenness += list_attr[6]

    def get_attr(self):
        '''
        Get attributes in the specified order: [imme_num, string_num, mem_num, arith_num, indegree, offspring, betweenness]
        '''
        return [self.imme_num, self.string_num, self.mem_num, self.arith_num, 
                self.indegree, self.offspring, self.betweenness]

    def set_ins_num(self, ins_num):
        '''Set total instruction count'''
        self.ins_num = ins_num

    def incre_mem_num(self):
        '''Increase memory operation count'''
        self.mem_num += 1

    def set_offspring(self, offspring):
        '''Set offspring count'''
        self.offspring = offspring

    def set_indegree(self, indegree):
        '''Set incoming edges count'''
        self.indegree = indegree

    def set_betweenness(self, betweenness):
        '''Set betweenness centrality'''
        self.betweenness = betweenness

    def add_string_constant(self, addr, string_value=None):
        '''Add a string constant reference'''
        if addr not in self.string_refs:
            self.string_refs.append(addr)
            if string_value:
                self.constant_details['string'].append((addr, string_value))

    def add_numeric_constant(self, value):
        '''Add a numeric constant'''
        if value not in self.constant_details['numeric']:
            self.constant_details['numeric'].append(value)


class BBWrapper(object):
    '''Wrapper for basic block with comparison operators'''
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


class BBCache(object):
    '''Cache for basic blocks with binary search capability'''
    def __init__(self):
        self.bb_cache_ = []
        self._build_cache()

    def _build_cache(self):
        '''Build sorted cache of all basic blocks'''
        for f in idautils.Functions():
            func = idaapi.get_func(f)
            if func is None:
                continue
            for bb in idaapi.FlowChart(func, flags=idaapi.FC_PREDS):
                self.bb_cache_.append(BBWrapper(bb.start_ea, bb))
        self.bb_cache_.sort()

    def find_block(self, ea):
        '''Binary search to find the basic block containing the given address'''
        idx = bisect_right(self.bb_cache_, BBWrapper(ea, None))
        if idx == 0:
            return None
        cand = self.bb_cache_[idx - 1].get_bb()
        # check ea is in range of address
        if cand and cand.start_ea <= ea < cand.end_ea:
            return cand
        return None
    
    def get_cache_size(self):
        '''Get the number of cached basic blocks'''
        return len(self.bb_cache_)


class ImprovedFunctionNameHasher:
    """
    Improved function name hasher with multiple algorithms and collision detection
    """
    def __init__(self, algorithm='sha256', seed=None, bit_width=32):
        """
        Initialize the hasher
        
        Args:
            algorithm: Hash algorithm ('fnv1a', 'djb2', 'sdbm', 'sha256', 'md5')
            seed: Optional seed value for reproducibility
            bit_width: Output bit width (32 or 64)
        """
        self.algorithm = algorithm.lower()
        self.bit_width = bit_width
        self.seed = seed if seed is not None else 0x811c9dc5
        self.collision_count = 0
        self.hash_map = {}
        
        # Set up masks and constants
        if bit_width == 32:
            self.mask = 0x7FFFFFFF
            self.fnv_prime = 0x01000193
            self.fnv_offset = 0x811c9dc5
        elif bit_width == 64:
            self.mask = 0x7FFFFFFFFFFFFFFF
            self.fnv_prime = 0x00000100000001B3
            self.fnv_offset = 0xcbf29ce484222325
        else:
            raise ValueError("bit_width must be 32 or 64")
    
    def fnv1a_hash(self, func_name: str) -> int:
        """FNV-1a hash algorithm"""
        if not func_name:
            return 0
            
        hash_val = self.fnv_offset
        for byte in func_name.encode('utf-8'):
            hash_val ^= byte
            hash_val = (hash_val * self.fnv_prime) & self.mask
        return hash_val
    
    def djb2_hash(self, func_name: str) -> int:
        """DJB2 hash algorithm"""
        if not func_name:
            return 0
            
        hash_val = 5381
        for char in func_name:
            hash_val = ((hash_val << 5) + hash_val + ord(char)) & self.mask
        return hash_val
    
    def cryptographic_hash(self, func_name: str, algorithm='sha256') -> int:
        """Use cryptographic hash functions for better collision resistance"""
        if not func_name:
            return 0
            
        if algorithm == 'md5':
            hash_obj = hashlib.md5(func_name.encode('utf-8'))
        elif algorithm == 'sha256':
            hash_obj = hashlib.sha256(func_name.encode('utf-8'))
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        bytes_needed = self.bit_width // 8
        hash_bytes = hash_obj.digest()[:bytes_needed]
        
        if self.bit_width == 32:
            hash_val = struct.unpack('>I', hash_bytes)[0]
        else:
            hash_val = struct.unpack('>Q', hash_bytes)[0]
        
        return hash_val & self.mask
    
    def hash_function_name(self, func_name: str) -> int:
        """Main hash function"""
        if not isinstance(func_name, str):
            func_name = str(func_name) if func_name is not None else ""
        
        func_name = func_name.strip()
        
        if self.algorithm == 'fnv1a':
            hash_val = self.fnv1a_hash(func_name)
        elif self.algorithm == 'djb2':
            hash_val = self.djb2_hash(func_name)
        elif self.algorithm in ['md5', 'sha256']:
            hash_val = self.cryptographic_hash(func_name, self.algorithm)
        else:
            raise ValueError(f"Unsupported algorithm: {self.algorithm}")
        
        # Check for collisions
        if hash_val in self.hash_map:
            if self.hash_map[hash_val] != func_name:
                self.collision_count += 1
                print(f"[WARNING] Hash collision: {func_name} vs {self.hash_map[hash_val]} -> {hash_val}")
        else:
            self.hash_map[hash_val] = func_name
        
        return hash_val


def list_square(lst):
    '''Square each element in a list'''
    return [key * key for key in lst]


def list_add(lst1, lst2):
    '''Add two lists element-wise'''
    if len(lst1) == 0:
        return deepcopy(lst2)
    elif len(lst2) == 0:
        return deepcopy(lst1)
    
    assert len(lst1) == len(lst2), "Lists must have the same length"
    return [lst1[i] + lst2[i] for i in range(len(lst1))]


def list_parameter_multiply(lst, multi):
    '''Multiply each element in list by a parameter'''
    return [i * multi for i in lst]


def sum_of_lists(lists):
    '''Sum a list of lists element-wise'''
    if not lists:
        return []
    
    result = []
    for lst in lists:
        result = list_add(result, lst)
    return result


def function_filter(f):
    '''Enhanced function filter with better error handling'''
    try:
        func_name = idc.get_func_name(f) or f'sub_{f:X}'
        
        # Skip AFL and common library functions
        skip_patterns = ['afl', '__libc', '__gconv', '__cxa', '_GLOBAL_', 'frame_dummy']
        if any(pattern in func_name.lower() for pattern in skip_patterns):
            return False
        
        # Check function flags
        flags = idc.get_func_attr(f, idc.FUNCATTR_FLAGS)
        if flags == idc.BADADDR:
            return False
            
        if (flags & idc.FUNC_LIB) or (flags & idc.FUNC_THUNK):
            return False
        
        # Check if function is in executable segment
        seg_name = idc.get_segm_name(f)
        if seg_name not in ['.text', 'CODE', '__text']:  # Common executable segment names
            return False
        
        # Check function size (skip very small functions that might be padding)
        func_obj = idaapi.get_func(f)
        if func_obj and (func_obj.end_ea - func_obj.start_ea) < 4:  # Minimum 4 bytes
            return False
        
        return True
        
    except Exception as e:
        logging.warning(f"Error filtering function {hex(f)}: {e}")
        return False


class Binary_Function:
    '''Enhanced binary function class'''
    def __init__(self, addr, name, hash_val):
        self.addr = addr
        self.name = name
        self.hash_val = hash_val
        
        # Attributes in specified order
        self.imme_num = 0
        self.string_num = 0
        self.mem_num = 0
        self.arith_num = 0
        self.indegree = 0
        self.offspring = 0.0
        self.betweenness = 0.0
        
        # Additional attributes
        self.ins_num = 0
        self.bb_num = 0

    def set_attr(self, imme_num, string_num, mem_num, arith_num, indegree, offspring, betweenness):
        '''Set all attributes'''
        self.imme_num = imme_num
        self.string_num = string_num
        self.mem_num = mem_num
        self.arith_num = arith_num
        self.indegree = indegree
        self.offspring = offspring
        self.betweenness = betweenness

    def set_attr_by_list(self, list_attr):
        '''Set attributes by list'''
        if len(list_attr) >= 7:
            self.imme_num = list_attr[0]
            self.string_num = list_attr[1]
            self.mem_num = list_attr[2]
            self.arith_num = list_attr[3]
            self.indegree = list_attr[4]
            self.offspring = list_attr[5]
            self.betweenness = list_attr[6]
    
    def get_attr(self):
        '''Get attributes in specified order'''
        return [self.imme_num, self.string_num, self.mem_num, self.arith_num,
                self.indegree, self.offspring, self.betweenness]

    def set_ins_num(self, ins_num):
        self.ins_num = ins_num

    def set_bb_num(self, bb_num):
        self.bb_num = bb_num


# Enhanced constant extraction functions
def is_meaningful_constant(value, addr, mnemonic):
    '''
    Enhanced filtering for meaningful constants
    '''
    # Skip very common values that are likely not interesting constants
    common_values = {0, 1, 2, 4, 8, 16, 32, 64, 255, 256, 512, 1024}
    if value in common_values:
        return False
    
    # Context-aware filtering based on instruction type
    if mnemonic in ['add', 'sub', 'lea'] and -128 <= value <= 128:
        return False  # Likely stack adjustments
    
    # Skip values that look like alignment or padding
    if value > 0 and (value & (value - 1)) == 0:  # Power of 2
        if value <= 4096:  # Common alignment values
            return False
    
    # Skip small negative values (likely offsets)
    if -256 <= value < 0:
        return False
    
    # Accept large values, addresses, and other meaningful constants
    return True


def get_string_at_address(addr):
    '''
    Enhanced string extraction from an address
    '''
    try:
        # Try IDA's built-in string detection first
        str_type = idc.get_str_type(addr)
        if str_type != -1:
            try:
                return idc.get_strlit_contents(addr).decode('utf-8', errors='ignore')
            except:
                pass
        
        # Manual extraction for various string types
        max_len = 512
        data = idc.get_bytes(addr, max_len)
        if not data:
            return None
        
        # Try ASCII string
        null_pos = data.find(b'\x00')
        if null_pos > 0:
            try:
                return data[:null_pos].decode('ascii', errors='ignore')
            except:
                pass
        
        # Try UTF-8 string
        if null_pos > 0:
            try:
                return data[:null_pos].decode('utf-8', errors='ignore')
            except:
                pass
        
        # Try wide character string (UTF-16)
        try:
            wide_data = data[::2]  # Take every other byte
            wide_null = wide_data.find(b'\x00')
            if wide_null > 0:
                return wide_data[:wide_null].decode('ascii', errors='ignore')
        except:
            pass
        
        return None
        
    except:
        return None


# Better approach - handle prefixes
def get_base_mnemonic(addr):
    """Extract base mnemonic, handling prefixes like 'rep'"""
    mnemonic = (idc.print_insn_mnem(addr) or '').lower()
    # Handle common prefixes
    prefixes = ['rep', 'repe', 'repz', 'repne', 'repnz', 'lock']
    for prefix in prefixes:
        if mnemonic.startswith(prefix + ' '):
            return mnemonic[len(prefix)+1:]
    return mnemonic


def extract_constants_from_instruction(addr, seen_constants, STRING_ADDRS):
    '''
    Modified version: string_num only counts strings that are recognized in idautils.Strings()
    '''
    constants = {'numeric': 0, 'string': 0, 'details': {'numeric': [], 'string': []}}
    
    try:
        mnemonic = get_base_mnemonic(addr).lower()
        # Skip instructions that do not contain useful constants
        skip_mnemonics = {'nop', 'ret', 'leave', 'int3', 'hlt', 'clc', 'stc', 'cld', 'std'}
        if mnemonic in skip_mnemonics:
            return constants

        # Iterate over operands
        for i in range(6):
            op_type = idc.get_operand_type(addr, i)
            if op_type == idaapi.o_void:
                break

            op_value = idc.get_operand_value(addr, i)

            if op_type == idaapi.o_imm:
                # Immediate numeric constants
                if is_meaningful_constant(op_value, addr, mnemonic):
                    const_key = f"imm_{op_value}_{addr}"
                    if const_key not in seen_constants:
                        constants['numeric'] += 1
                        constants['details']['numeric'].append(op_value)
                        seen_constants.add(const_key)

                # Check if it is a string address (must be in STRING_ADDRS)
                if op_value in STRING_ADDRS:
                    str_key = f"str_{op_value}_{addr}"
                    if str_key not in seen_constants:
                        string_content = get_string_at_address(op_value)
                        constants['string'] += 1
                        constants['details']['string'].append((op_value, string_content))
                        seen_constants.add(str_key)

            elif op_type in [idaapi.o_mem, idaapi.o_displ, idaapi.o_near, idaapi.o_far]:
                # Memory operands may also point to strings
                if op_value in STRING_ADDRS:
                    str_key = f"str_{op_value}_{addr}"
                    if str_key not in seen_constants:
                        string_content = get_string_at_address(op_value)
                        constants['string'] += 1
                        constants['details']['string'].append((op_value, string_content))
                        seen_constants.add(str_key)

    except Exception as e:
        logging.warning(f"Error extracting constants at {hex(addr)}: {e}")

    return constants


def get_all_ida_strings():
    '''
    Get all strings detected by IDA Pro
    '''
    STRING_ADDRS = set()
    try:
        for s in idautils.Strings():
            if hasattr(s, "ea"):  # Old versions of IDA return string_item_t with field 'ea'
                STRING_ADDRS.add(s.ea)
            else:  # In some versions, Strings() directly returns the address
                STRING_ADDRS.add(int(s))
    except Exception as e:
        logging.warning(f"Error building string set: {e}")
    
    return STRING_ADDRS


def is_memory_operation(addr, mnemonic):
    '''
    IMPROVED: More accurate memory operation detection
    '''
    try:
        # Direct memory instructions (from utils.py)
        if mnemonic in direct_memory_insns:
            return True
        
        # Check operands more thoroughly
        has_memory_operand = False
        
        for i in range(8):  # Check more operands
            op_type = idc.get_operand_type(addr, i)
            
            if op_type == idaapi.o_void:
                break
            
            # Memory operand types
            if op_type in [idaapi.o_mem, idaapi.o_displ, idaapi.o_phrase]:
                has_memory_operand = True
                break
            
            # Additional check: look for memory addressing in operand text
            op_text = idc.print_operand(addr, i).lower()
            
            # Memory addressing patterns
            if ('[' in op_text and ']' in op_text):
                has_memory_operand = True
                break
            
            # Segment register usage often indicates memory access
            if any(seg + ':' in op_text for seg in ['ds', 'es', 'ss', 'cs', 'fs', 'gs']):
                has_memory_operand = True
                break
        
        if has_memory_operand:
            return True
        
        # Special cases: function calls to memory-related functions
        if mnemonic == 'call':
            try:
                # Get call target name
                op_text = idc.print_operand(addr, 0)
                func_name = None
                
                # Try to get function name at call target
                call_target = idc.get_operand_value(addr, 0)
                if call_target != idc.BADADDR:
                    func_name = idc.get_func_name(call_target)
                
                if not func_name:
                    func_name = op_text
                
                if func_name:
                    func_name_lower = func_name.lower()
                    for mem_func in mem_insn_functions:
                        if mem_func in func_name_lower:
                            return True
            except:
                pass
        
        return False
        
    except Exception as e:
        logging.warning(f"Error checking memory operation at {hex(addr)}: {e}")
        return False


def validate_memory_detection():
    '''
    Validate memory operation detection by sampling some instructions
    '''
    print("[+] Validating memory operation detection...")
    
    sample_count = 0
    memory_count = 0
    
    for f in idautils.Functions():
        if sample_count >= 100:  # Sample first 100 functions
            break
            
        if not function_filter(f):
            continue
            
        func_obj = idaapi.get_func(f)
        if func_obj is None:
            continue
            
        current_addr = func_obj.start_ea
        func_end = func_obj.end_ea
        
        while current_addr < func_end and sample_count < 100:
            sample_count += 1
            mnemonic = get_base_mnemonic(current_addr)
            
            if is_memory_operation(current_addr, mnemonic):
                memory_count += 1
                if sample_count <= 20:  # Show first 20 examples
                    disasm = idc.generate_disasm_line(current_addr, 0)
                    print(f"    Memory op: {hex(current_addr)} - {disasm}")
            
            current_addr = idc.next_head(current_addr)
            if current_addr == idc.BADADDR:
                break
    
    print(f"[+] Memory detection validation: {memory_count}/{sample_count} instructions involve memory")
    return True
