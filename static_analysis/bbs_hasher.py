'''
Simplified IDA Pro script for AFL instrumentation analysis
Records cur_loc to function basic block addresses mapping
Format: {"cur_loc": [bb_addr1, bb_addr2, ...], ...}
'''
import os
import sys
import json
import time
import logging
from collections import defaultdict
from typing import Dict, Set, List, Tuple, Optional

import idc
import idaapi
import idautils
import ida_nalt

from utils import BBCache, function_filter, ImprovedFunctionNameHasher, get_base_mnemonic, FUNC_HIT_SHM_SIZE

# Configure logging for AFL analysis
afl_logger = logging.getLogger('afl_analysis')
afl_handler = logging.FileHandler('afl_analysis_errors.log')
afl_handler.setLevel(logging.DEBUG)
afl_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
afl_handler.setFormatter(afl_formatter)
afl_logger.addHandler(afl_handler)
afl_logger.setLevel(logging.DEBUG)


class AFLLocationExtractor:
    """Simplified AFL location extractor for cur_loc to basic block addresses mapping"""

    def __init__(self, bb_cache=None, binary_path=None, output_dir=None):
        """
        Initialize AFL Location Extractor
        
        Args:
            bb_cache: Existing BBCache instance (optional)
            binary_path: Path to binary (optional, defaults to IDA's current binary)
            output_dir: Output directory (optional, defaults to binary directory)
        """
        # Binary information
        self.binary_path = binary_path or ida_nalt.get_input_file_path()
        self.dir_name = output_dir or os.path.dirname(self.binary_path)
        self.base_name = os.path.basename(self.binary_path)
        
        # Address range
        self.min_addr = idc.get_inf_attr(idc.INF_MIN_EA)
        self.max_addr = idc.get_inf_attr(idc.INF_MAX_EA)
        
        # Main data structure: cur_loc -> [basic_block_addresses]
        self.loc2addrs: Dict[int, List[str]] = {}
        
        # Function tracking
        self.func_entry_locs: Dict[int, int] = {}  # func_addr -> cur_loc
        self.all_functions_addrs = list(idautils.Functions())
        
        # Cache and utilities
        self.bb_cache = bb_cache or BBCache()
        self.hasher = ImprovedFunctionNameHasher(algorithm='sha256', bit_width=32)
        
        # Statistics
        self.stats = {
            'processed_functions': 0,
            'instrumented_functions': 0,
            'total_basic_blocks': 0,
            'analysis_time': 0,
            'functions_without_afl': 0
        }
        
        # Results storage
        self.results = {}
    
    def get_block_hash(self, block) -> int:
        """
        Extract AFL instrumentation hash from basic block
        Returns:
            -1: No AFL instrumentation found
            >=0: Actual hash value
        """
        start_ea, end_ea = block.start_ea, block.end_ea
        current_addr = start_ea
        
        # AFL pattern detection state machine
        afl_pattern_state = 0  # 0: initial, 1: found fs:0, 2: found add offset, 3: found movsxd, 4: found area ptr
        temp_register = None   # Track which register is used for TLS access
        area_ptr_register = None  # Track which register holds AFL area pointer
        prev_loc_register = None  # Track register holding previous location
        
        try:
            while current_addr < end_ea and current_addr != idc.BADADDR:
                instruction_line = idc.generate_disasm_line(current_addr, 0)
                mnemonic = get_base_mnemonic(current_addr).lower()
                
                # State machine for AFL instrumentation pattern detection
                if mnemonic == "mov" and ("fs:0" in instruction_line or "gs:0" in instruction_line):
                    # Step 1: mov rax, fs:0 (or gs:0 for 32-bit) - TLS access
                    temp_register = idc.print_operand(current_addr, 0).strip()
                    afl_pattern_state = 1
                    afl_logger.debug(f"AFL pattern step 1 at {hex(current_addr)}: TLS access, reg={temp_register}")
                    
                elif (afl_pattern_state == 1 and mnemonic == "add" and 
                      temp_register and temp_register in instruction_line):
                    # Step 2: add rax, cs:__afl_area_ptr or similar offset
                    if "cs:" in instruction_line or "__afl" in instruction_line:
                        afl_pattern_state = 2
                        afl_logger.debug(f"AFL pattern step 2 at {hex(current_addr)}: Add AFL offset")
                    
                elif (afl_pattern_state == 2 and mnemonic in ["mov", "movsxd"] and 
                      temp_register and temp_register in instruction_line):
                    # Step 3: movsxd rcx, dword ptr [rax] - load previous location
                    if "[" in instruction_line and "]" in instruction_line:
                        prev_loc_register = idc.print_operand(current_addr, 0).strip()
                        afl_pattern_state = 3
                        afl_logger.debug(f"AFL pattern step 3 at {hex(current_addr)}: Load prev_loc to {prev_loc_register}")
                    
                elif (afl_pattern_state == 3 and mnemonic == "mov" and 
                      "[" in instruction_line and "]" in instruction_line and
                      ("r14" in instruction_line or "r15" in instruction_line or "__afl_area_ptr" in instruction_line)):
                    # Step 4: mov rdx, [r14] or similar - get AFL area pointer
                    area_ptr_register = idc.print_operand(current_addr, 0).strip()
                    afl_pattern_state = 4
                    afl_logger.debug(f"AFL pattern step 4 at {hex(current_addr)}: Get area ptr to {area_ptr_register}")
                    
                elif afl_pattern_state >= 3 and mnemonic == "xor":
                    # Step 5: xor prev_loc, cur_loc - This is where we extract cur_loc!
                    operand1 = idc.print_operand(current_addr, 0).strip()
                    operand2 = idc.print_operand(current_addr, 1).strip()
                    
                    # Check if this is XORing with a constant (cur_loc)
                    # The constant can be in hex (ending with 'h'), decimal, or as immediate value
                    cur_loc_value = None
                    
                    # Try to get the immediate value from operand 1 or 2
                    for i in [0, 1]:
                        op_type = idc.get_operand_type(current_addr, i)
                        if op_type == idaapi.o_imm:  # Immediate operand
                            op_value = idc.get_operand_value(current_addr, i)
                            if op_value != idc.BADADDR and op_value > 0:
                                cur_loc_value = op_value % FUNC_HIT_SHM_SIZE
                                break
                    
                    if cur_loc_value is not None:
                        afl_logger.debug(f"AFL pattern COMPLETE at {hex(current_addr)}: Found cur_loc = {hex(cur_loc_value)}")
                        return cur_loc_value
                
                # Reset state if pattern is broken by control flow instructions
                if mnemonic in ["call", "ret", "jmp"] and "short" not in instruction_line:
                    if afl_pattern_state > 0:
                        afl_logger.debug(f"AFL pattern reset at {hex(current_addr)} due to {mnemonic}")
                        afl_pattern_state = 0
                        temp_register = None
                        area_ptr_register = None
                        prev_loc_register = None
                
                # Some flexibility for intervening instructions
                elif afl_pattern_state > 0:
                    # Allow some common instructions without resetting
                    allowed_intervening = {"nop", "push", "pop", "test", "cmp"}
                    if mnemonic not in allowed_intervening:
                        # Check if current instruction uses our tracked registers
                        uses_tracked_reg = False
                        if temp_register and temp_register in instruction_line:
                            uses_tracked_reg = True
                        if area_ptr_register and area_ptr_register in instruction_line:
                            uses_tracked_reg = True
                        if prev_loc_register and prev_loc_register in instruction_line:
                            uses_tracked_reg = True
                            
                        # If instruction doesn't use tracked registers, we might be drifting
                        if not uses_tracked_reg and afl_pattern_state > 2:
                            afl_logger.debug(f"AFL pattern drift at {hex(current_addr)}: {mnemonic}")
                            # Don't reset immediately, but be more strict
                
                current_addr = idc.next_head(current_addr)
                
        except Exception as e:
            afl_logger.error(f"Error analyzing block {hex(block.start_ea)}: {e}")
        
        # If we reach here, no AFL instrumentation was found
        return -1
    
    def find_function_entry_cur_loc(self, func_addr: int) -> int:
        """
        Find cur_loc from the entry basic block of a function
        Returns:
            -1: No AFL instrumentation found in entry block
            >=0: cur_loc value from entry block
        """
        try:
            func_obj = idaapi.get_func(func_addr)
            if func_obj is None:
                return -1
                
            func_cfg = idaapi.FlowChart(func_obj, flags=idaapi.FC_PREDS)
            basic_blocks = list(func_cfg)
            
            if not basic_blocks:
                afl_logger.warning(f'FlowChart of {hex(func_addr)} is empty')
                return -1
            
            # Check ALL basic blocks for AFL instrumentation, starting with entry
            for block in basic_blocks:
                cur_loc = self.get_block_hash(block)
                if cur_loc > 0:
                    afl_logger.debug(f"Function {hex(func_addr)} found cur_loc: {hex(cur_loc)} in block {hex(block.start_ea)}")
                    return cur_loc
            
            return -1
                    
        except Exception as e:
            afl_logger.error(f"Error processing function {hex(func_addr)}: {e}")
            return -1
    
    def get_all_basic_block_addresses_in_function(self, func_addr: int) -> List[str]:
        """
        Get all basic block addresses in a function as hex strings
        """
        bb_addresses = []
        
        try:
            func_obj = idaapi.get_func(func_addr)
            if func_obj is None:
                return bb_addresses
                
            func_cfg = idaapi.FlowChart(func_obj, flags=idaapi.FC_PREDS)
            
            for bb in func_cfg:
                bb_addresses.append(bb.start_ea)
                
        except Exception as e:
            afl_logger.error(f"Error getting basic blocks for function {hex(func_addr)}: {e}")
        
        return bb_addresses
    
    def analyze_function(self, func_addr: int) -> bool:
        """
        Analyze a single function for AFL instrumentation
        Returns True if AFL instrumentation found, False otherwise
        """
        func_name = idc.get_func_name(func_addr) or f"sub_{func_addr:X}"
        
        # Find cur_loc from entry block
        cur_loc = self.find_function_entry_cur_loc(func_addr)
        
        if cur_loc <= 0:
            afl_logger.debug(f"No AFL instrumentation in function {func_name}")
            self.stats['functions_without_afl'] += 1
            return False
        
        # Get all basic block addresses in this function
        bb_addresses = self.get_all_basic_block_addresses_in_function(func_addr)
        
        if not bb_addresses:
            afl_logger.warning(f"No basic blocks found in function {func_name}")
            return False
        
        # Map cur_loc to all basic block addresses in this function
        self.loc2addrs[cur_loc] = bb_addresses
        self.func_entry_locs[func_addr] = cur_loc
        
        self.stats['total_basic_blocks'] += len(bb_addresses)
        self.stats['instrumented_functions'] += 1
        
        afl_logger.info(f"Function {func_name} at {hex(func_addr)}: cur_loc={hex(cur_loc)}, {len(bb_addresses)} basic blocks")
        
        return True
    
    def get_results(self):
        """Get analysis results as dictionary"""
        # Convert cur_loc keys to hex strings for JSON serialization
        loc2addrs_json = {str(k): v for k, v in self.loc2addrs.items()}
        
        return {
            'loc2addrs': loc2addrs_json,
            'func_entry_locs': {hex(k): hex(v) for k, v in self.func_entry_locs.items()},
            'statistics': self.stats
        }
    
    def save_results(self, save_files=True):
        """Save analysis results to JSON files"""
        if not save_files:
            return
            
        print("[+] Saving AFL analysis results...")
        results = self.get_results()
        
        # Save main loc2addrs mapping
        loc2addrs_path = os.path.join(self.dir_name, self.base_name + '_loc2addrs.json')
        try:
            with open(loc2addrs_path, 'w') as f:
                json.dump(results['loc2addrs'], f, indent=2, sort_keys=True)
            print(f"    Saved: {self.base_name}_loc2addrs.json")
        except Exception as e:
            afl_logger.error(f"Error saving loc2addrs: {e}")
        
        # Save function entry locations mapping
        func_entry_path = os.path.join(self.dir_name, self.base_name + '_func_entry_locs.json')
        try:
            with open(func_entry_path, 'w') as f:
                json.dump(results['func_entry_locs'], f, indent=4, sort_keys=True)
            print(f"    Saved: {self.base_name}_func_entry_locs.json")
        except Exception as e:
            afl_logger.error(f"Error saving func_entry_locs: {e}")
        
        # Save analysis summary
        summary = {
            'binary_name': self.base_name,
            'analysis_timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
            'statistics': self.stats,
            'total_locations': len(self.loc2addrs),
            'instrumentation_coverage': {
                'instrumented_functions': self.stats['instrumented_functions'],
                'total_functions': len(self.all_functions_addrs),
                'coverage_percentage': (self.stats['instrumented_functions'] / max(len(self.all_functions_addrs), 1)) * 100
            },
            'description': 'AFL cur_loc to basic block addresses mapping',
            'format': 'loc2addrs maps each function entry cur_loc to all basic block addresses in that function'
        }
        
        summary_path = os.path.join(self.dir_name, self.base_name + '_afl_summary.json')
        try:
            with open(summary_path, 'w') as f:
                json.dump(summary, f, indent=4)
            print(f"    Saved: {self.base_name}_afl_summary.json")
        except Exception as e:
            afl_logger.error(f"Error saving summary: {e}")
        
        # Store results for integration with main analysis
        self.results = results
    
    def run_analysis(self, save_files=True):
        """Run the complete AFL location analysis"""
        print(f"[+] Starting simplified AFL location analysis for: {self.base_name}")
        start_time = time.time()
        
        # Process all functions
        all_functions = [f for f in self.all_functions_addrs if function_filter(f)]
        functions_count = len(all_functions)
        
        print(f"[+] Processing {functions_count} filtered functions...")
        
        instrumented_count = 0
        for i, func_addr in enumerate(all_functions):
            func_name = idc.get_func_name(func_addr) or f"sub_{func_addr:X}"
            
            # Show progress every 100 functions or at the end
            if i % 100 == 0 or i == functions_count - 1:
                print(f'[+] AFL analysis [{i + 1}/{functions_count}]: {func_name} at {hex(func_addr)}')
            
            # Analyze function for AFL instrumentation
            if self.analyze_function(func_addr):
                instrumented_count += 1
            
            self.stats['processed_functions'] += 1
        
        # Update statistics
        self.stats['analysis_time'] = time.time() - start_time
        
        # Save results
        self.save_results(save_files)
        
        # Print final summary
        print(f"\n[+] AFL analysis completed in {self.stats['analysis_time']:.2f} seconds")
        print(f"    Total cur_loc mappings: {len(self.loc2addrs)}")
        print(f"    Instrumented functions: {self.stats['instrumented_functions']}")
        print(f"    Functions without AFL: {self.stats['functions_without_afl']}")
        print(f"    Total basic blocks mapped: {self.stats['total_basic_blocks']}")
        print(f"    Coverage: {instrumented_count}/{functions_count} functions ({(instrumented_count/max(functions_count,1)*100):.1f}%)")
        
        return self.stats['instrumented_functions'] > 0


def main():
    """Main entry point"""
    try:
        extractor = AFLLocationExtractor()
        success = extractor.run_analysis()
        
        if success:
            print('[+] AFL location extraction completed successfully!')
        else:
            print('[!] AFL location extraction completed but no instrumentation found')
        
    except Exception as e:
        print(f"[ERROR] AFL analysis failed: {e}")
        afl_logger.error(f"Main analysis failed: {e}", exc_info=True)


if __name__ == '__main__':
    main()
