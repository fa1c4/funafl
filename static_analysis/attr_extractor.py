'''
IDA Pro script to extract Attributed Control Flow Graph (ACFG) from binary program
Attributes order: [imme_num, string_num, mem_num, arith_num, indegree, offspring, betweenness]
'''
import os
import networkx as nx
import sys
import json
import math
import pickle
import time
from collections import defaultdict
from copy import deepcopy

import idaapi
import idautils
import idc
import ida_nalt

from utils import *
from bbs_hasher import AFLLocationExtractor

# Set parameters
partition = parameters['partition']
attributes_num = parameters['attributes_num']

# Get binary information
binary_path = ida_nalt.get_input_file_path()
dir_name = os.path.dirname(binary_path)
base_name = os.path.basename(binary_path)

# Get address range
min_addr = idc.get_inf_attr(idc.INF_MIN_EA)
max_addr = idc.get_inf_attr(idc.INF_MAX_EA)

# Initialize data structures
addr2funcname, funchash2name, addr2node = {}, {}, {}
func2bbs = defaultdict(list)
loc2functions, loc2bbs = defaultdict(set), defaultdict(set)
CFG = nx.DiGraph()  # Complete control flow graph for analysis
CG = nx.DiGraph()   # Final attributed graph (subset for AFL if needed)

# Global BB cache
bb_cache = None
_GLOBAL_HASHER = ImprovedFunctionNameHasher(algorithm='sha256', bit_width=32)
STRING_ADDRS = None

def function_name_hash(func_name: str) -> int:
    """
    Standalone function name hash with better collision resistance
    """
    return _GLOBAL_HASHER.hash_function_name(func_name)


def validate_attributes():
    '''Enhanced attribute validation with detailed reporting'''
    global CFG, attributes_num  # Use CFG consistently
    
    validation_errors = []
    
    for i, node in enumerate(CFG.nodes()):
        attrs = node.get_attr()
        
        # Check attribute count
        if len(attrs) != attributes_num:
            error_msg = f"Node {hex(node.addr)} has {len(attrs)} attributes, expected {attributes_num}"
            validation_errors.append(error_msg)
            continue
        
        # Check for invalid values
        for j, attr in enumerate(attrs):
            attr_name = ATTRS[j] if j < len(ATTRS) else f"attr_{j}"
            
            if math.isnan(attr):
                error_msg = f"Node {hex(node.addr)} has NaN for {attr_name}"
                validation_errors.append(error_msg)
            elif math.isinf(attr):
                error_msg = f"Node {hex(node.addr)} has infinite value for {attr_name}"
                validation_errors.append(error_msg)
            elif attr < 0 and attr_name not in ['betweenness']:  # Some attributes can be negative
                error_msg = f"Node {hex(node.addr)} has negative value {attr} for {attr_name}"
                validation_errors.append(error_msg)
    
    # Report validation results
    if validation_errors:
        print(f"[WARNING] Found {len(validation_errors)} validation errors:")
        for error in validation_errors[:10]:  # Show first 10 errors
            print(f"  {error}")
        if len(validation_errors) > 10:
            print(f"  ... and {len(validation_errors) - 10} more errors")
        
        # Log all errors
        for error in validation_errors:
            logging.error(error)
        
        return False
    
    print("[+] Attribute validation passed!")
    return True


def normalization_min_max(start=[0]*attributes_num, end=[100]*attributes_num):
    '''Min-max normalization to specified range'''
    global CFG, attributes_num  # Use CFG consistently
    
    if len(CFG.nodes()) == 0:
        return
    
    # Find min and max values for each attribute
    max_values = [float('-inf')] * attributes_num
    min_values = [float('inf')] * attributes_num
    
    for node in CFG.nodes():
        attrs = node.get_attr()
        for j, attr in enumerate(attrs):
            if attr > max_values[j]:
                max_values[j] = attr
            if attr < min_values[j]:
                min_values[j] = attr
    
    # Normalize attributes
    for node in CFG.nodes():
        attrs = node.get_attr()
        new_attrs = []
        
        for j, attr in enumerate(attrs):
            range_val = max_values[j] - min_values[j]
            if range_val == 0:
                range_val = 1  # Avoid division by zero
            
            normalized = start[j] + (end[j] - start[j]) * ((attr - min_values[j]) / range_val)
            new_attrs.append(normalized)
        
        node.set_attr_by_list(new_attrs)


def robust_logarithmic_normalization(epsilon=1e-6):
    '''Robust logarithmic normalization with proper zero handling'''
    global CFG, attributes_num  # Use CFG consistently
    
    # Collect positive values for each attribute
    attr_positive_values = [[] for _ in range(attributes_num)]
    
    for node in CFG.nodes():
        attrs = node.get_attr()
        for j, attr in enumerate(attrs):
            if attr > 0:
                attr_positive_values[j].append(attr)
    
    # Calculate minimum positive values
    min_positive = []
    for j in range(attributes_num):
        if attr_positive_values[j]:
            min_positive.append(min(attr_positive_values[j]))
        else:
            min_positive.append(epsilon)
    
    # Apply log transformation
    record_min_value = [100.0] * attributes_num
    
    for node in CFG.nodes():
        attrs = node.get_attr()
        new_attrs = []
        
        for j, attr in enumerate(attrs):
            if attr > 0:
                log_value = math.log(attr / min_positive[j])
                new_attrs.append(log_value)
                if log_value < record_min_value[j]:
                    record_min_value[j] = log_value
            else:
                new_attrs.append(0.0)
        
        node.set_attr_by_list(new_attrs)
    
    # Handle zero values by setting them slightly below minimum
    for node in CFG.nodes():
        attrs = node.get_attr()
        new_attrs = []
        
        for j, attr in enumerate(attrs):
            if attr == 0.0:
                new_attrs.append(record_min_value[j] - 0.001)
            else:
                new_attrs.append(attr)
        
        node.set_attr_by_list(new_attrs)


def standardize_attributes_max_norm():
    '''Max-norm standardization: r'_ij = x_ij / max_j(x_ij)'''
    global CFG, attributes_num
    
    if len(CFG.nodes()) == 0:
        return
    
    print("[+] Applying max-norm standardization...")
    
    # Find max values for each attribute
    max_values = [float('-inf')] * attributes_num
    
    for node in CFG.nodes():
        attrs = node.get_attr()
        for j, attr in enumerate(attrs):
            if attr > max_values[j]:
                max_values[j] = attr
    
    # Apply max-norm standardization
    standardized_count = 0
    for node in CFG.nodes():
        attrs = node.get_attr()
        new_attrs = []
        
        for j, attr in enumerate(attrs):
            if max_values[j] == 0:
                # Handle zero max case
                new_attrs.append(0.0)
            else:
                # r'_ij = x_ij / max_j(x_ij)
                standardized_val = attr / max_values[j]
                new_attrs.append(standardized_val)
        
        node.set_attr_by_list(new_attrs)
        standardized_count += 1
    
    print(f"[+] Standardized {standardized_count} nodes using max-norm")
    
    # Log max values used for standardization
    for j, max_val in enumerate(max_values):
        attr_name = ATTRS[j] if j < len(ATTRS) else f"attr_{j}"
        print(f"    {attr_name}: max = {max_val:.6f}")


def save_standardized_attributes():
    '''Save standardized attributes for analysis'''
    global base_name, dir_name, CFG
    
    standardized_attrs = {}
    for node in CFG.nodes():
        standardized_attrs[str(node.addr)] = node.get_attr()
    
    std_path = os.path.join(dir_name, base_name + '_bb2attributes_standard.json')
    with open(std_path, 'w') as f:
        json.dump(standardized_attrs, f, indent=2)
    
    print(f"[+] Standardized attributes saved to: {std_path}")


def attributed_pagerank(iterations=3, damping_factor=0.85):
    '''
    Improved PageRank algorithm for attribute propagation
    Attributes order: [imme_num, string_num, mem_num, arith_num, indegree, offspring, betweenness]
    '''
    global CFG, addr2node  # Use CFG consistently
    
    start_time = time.time()
    
    for iteration in range(iterations):
        print(f"[+] PageRank iteration {iteration + 1}/{iterations}")
        
        # Store updates to apply atomically
        node_updates = {}
        
        # Calculate updates for all nodes
        for node in CFG.nodes():
            in_degree = CFG.in_degree(node)
            current_attrs = node.get_attr()
            
            if in_degree == 0:
                # Nodes with no incoming edges keep their attributes
                node_updates[node.addr] = current_attrs
                continue
            
            # Collect contributions from predecessors
            pred_contributions = []
            for pred in CFG.predecessors(node):
                out_degree = max(float(CFG.out_degree(pred)), 1.0)
                pred_attrs = pred.get_attr()
                
                # PageRank contribution: divide by out_degree
                contribution = list_parameter_multiply(pred_attrs, 1.0 / out_degree)
                pred_contributions.append(contribution)
            
            if pred_contributions:
                sum_contributions = sum_of_lists(pred_contributions)
                
                # Apply PageRank formula with damping
                propagated = list_parameter_multiply(sum_contributions, damping_factor / in_degree)
                baseline = list_parameter_multiply(current_attrs, (1 - damping_factor))
                new_attributes = list_add(propagated, baseline)
                
                node_updates[node.addr] = new_attributes
            else:
                node_updates[node.addr] = current_attrs
        
        # Apply all updates atomically
        for addr, new_attrs in node_updates.items():
            if addr in addr2node:
                addr2node[addr].set_attr_by_list(new_attrs)
        
        # Log progress
        elapsed_time = (time.time() - start_time) / 60
        print(f"[+] Iteration {iteration + 1} completed in {elapsed_time:.2f} minutes")


def attributed_pagerank_convergence(iterations=3, damping_factor=0.85, convergence_threshold=1e-6):
    '''
    Improved PageRank algorithm with convergence checking
    '''
    global CFG, addr2node  # Use CFG consistently
    
    start_time = time.time()
    prev_node_attrs = {}
    
    # Initialize previous attributes
    for node in CFG.nodes():
        prev_node_attrs[node.addr] = node.get_attr().copy()
    
    for iteration in range(iterations):
        print(f"[+] PageRank iteration {iteration + 1}/{iterations}")
        
        node_updates = {}
        max_change = 0.0
        
        # Calculate updates for all nodes
        for node in CFG.nodes():
            in_degree = CFG.in_degree(node)
            current_attrs = node.get_attr()
            
            if in_degree == 0:
                # Nodes with no incoming edges keep their attributes
                node_updates[node.addr] = current_attrs
            else:
                # Collect contributions from predecessors
                pred_contributions = []
                total_weight = 0.0
                
                for pred in CFG.predecessors(node):
                    out_degree = max(float(CFG.out_degree(pred)), 1.0)
                    pred_attrs = pred.get_attr()
                    
                    # Weight by inverse of out_degree (more focused paths have higher weight)
                    weight = 1.0 / out_degree
                    total_weight += weight
                    
                    contribution = list_parameter_multiply(pred_attrs, weight)
                    pred_contributions.append(contribution)
                
                if pred_contributions and total_weight > 0:
                    sum_contributions = sum_of_lists(pred_contributions)
                    # Normalize by total weight
                    normalized_contrib = list_parameter_multiply(sum_contributions, 1.0 / total_weight)
                    
                    # Apply PageRank formula
                    propagated = list_parameter_multiply(normalized_contrib, damping_factor)
                    baseline = list_parameter_multiply(current_attrs, (1 - damping_factor))
                    new_attributes = list_add(propagated, baseline)
                    
                    node_updates[node.addr] = new_attributes
                else:
                    node_updates[node.addr] = current_attrs
            
            # Calculate change for convergence check
            if node.addr in prev_node_attrs:
                change = sum(abs(a - b) for a, b in zip(node_updates[node.addr], prev_node_attrs[node.addr]))
                max_change = max(max_change, change)
        
        # Apply all updates atomically
        for addr, new_attrs in node_updates.items():
            if addr in addr2node:
                addr2node[addr].set_attr_by_list(new_attrs)
                prev_node_attrs[addr] = new_attrs.copy()
        
        # Check for convergence
        if max_change < convergence_threshold:
            print(f"[+] Converged after {iteration + 1} iterations (max_change: {max_change:.8f})")
            break
        
        elapsed_time = (time.time() - start_time) / 60
        print(f"[+] Iteration {iteration + 1} completed in {elapsed_time:.2f} minutes (max_change: {max_change:.6f})")


def build_call_graph():
    '''Build call graph using entry blocks of functions as nodes'''
    global CG, addr2node  # Use CG consistently
    
    print("[+] Building call graph...")
    call_edges = 0
    func_entry_blocks = {}  # func_addr -> entry_block_node
    
    # First pass: Find entry blocks for all functions and add to CG
    for f in idautils.Functions():
        if not function_filter(f):
            continue
            
        func_obj = idaapi.get_func(f)
        if func_obj is None:
            continue
            
        # Get entry block (first basic block of function)
        entry_addr = func_obj.start_ea
        entry_block = addr2node.get(entry_addr)
        
        if entry_block is not None:
            func_entry_blocks[f] = entry_block
            # Add entry block to call graph if not already there
            if not CG.has_node(entry_block):
                CG.add_node(entry_block)
    
    print(f"[+] Found {len(func_entry_blocks)} function entry blocks")
    
    # Second pass: Build call edges between entry blocks
    for f in idautils.Functions():
        if not function_filter(f):
            continue
            
        caller_func = idc.get_func_name(f) or f'sub_{f:X}'
        caller_entry_block = func_entry_blocks.get(f)
        
        if caller_entry_block is None:
            continue
        
        # Iterate through all instructions in the function
        func_obj = idaapi.get_func(f)
        if func_obj is None:
            continue
            
        current_addr = func_obj.start_ea
        func_end = func_obj.end_ea
        
        while current_addr < func_end:
            mnemonic = get_base_mnemonic(current_addr)
            
            # Check for call instructions
            if mnemonic == 'call':
                # Get call target
                call_target = idc.get_operand_value(current_addr, 0)
                
                if call_target != idc.BADADDR:
                    # Check if target is a valid function
                    target_func_addr = idc.get_func_attr(call_target, idc.FUNCATTR_START)
                    
                    if target_func_addr != idc.BADADDR and function_filter(target_func_addr):
                        target_entry_block = func_entry_blocks.get(target_func_addr)
                        
                        if target_entry_block is not None:
                            # Add edge between entry blocks in call graph
                            if not CG.has_edge(caller_entry_block, target_entry_block):
                                CG.add_edge(caller_entry_block, target_entry_block)
                                call_edges += 1
            
            current_addr = idc.next_head(current_addr)
            if current_addr == idc.BADADDR:
                break
    
    print(f"[+] Call graph built: {len(CG.nodes())} entry block nodes, {call_edges} call relationships")
    
    return CG


def set_graph_metrics():
    '''
    Calculate and set graph metrics on the COMPLETE CFG
    This ensures accurate indegree, offspring, and betweenness calculations
    '''
    global CFG  # Use CFG consistently
    
    num_nodes = CFG.number_of_nodes()
    if num_nodes == 0:
        return
        
    print(f"[+] Calculating graph metrics for {num_nodes} nodes...")
    
    # Calculate betweenness centrality with sampling for large graphs
    sample_size = None if num_nodes <= 2000 else min(num_nodes, 10000)
    
    start_time = time.time()
    try:
        betweenness_dict = nx.betweenness_centrality(CFG, normalized=True, k=sample_size)
        elapsed_time = (time.time() - start_time) / 60
        print(f"[+] Betweenness centrality calculated in {elapsed_time:.2f} minutes")
    except Exception as e:
        print(f"[WARNING] Betweenness calculation failed: {e}")
        betweenness_dict = {node: 0.0 for node in CFG.nodes()}
    
    # Set metrics for each node using the COMPLETE graph
    for node in CFG.nodes():
        # Set indegree from CFG
        indegree = CFG.in_degree(node)
        node.set_indegree(indegree)
        
        # Set offspring count (descendants in CFG)
        try:
            offspring = float(len(nx.descendants(CFG, node)))
            node.set_offspring(offspring)
        except Exception as e:
            print(f"[WARNING] Offspring calculation failed for {hex(node.addr)}: {e}")
            node.set_offspring(0.0)
        
        # Set betweenness centrality
        betweenness = betweenness_dict.get(node, 0.0)
        node.set_betweenness(betweenness)
    
    print(f"[+] Graph metrics completed:")
    print(f"    Total nodes in CFG: {num_nodes}")
    print(f"    Total edges in CFG: {CFG.number_of_edges()}")


def analyze_basic_block(block, func_name, func_name_hash, check_afl=True):
    '''
    Analyze a basic block and extract attributes with proper constants extraction
    Returns BBlock with attributes: [imme_num, string_num, mem_num, arith_num, indegree, offspring, betweenness]
    '''
    global STRING_ADDRS

    # Initialize counters
    imme_num = 0      # Numeric constants count
    string_num = 0    # String constants count  
    mem_num = 0       # Memory operation instructions count
    arith_num = 0     # Arithmetic operations count
    ins_num = 0       # Total instruction count
   
    start_ea, end_ea = block.start_ea, block.end_ea
    current_addr = start_ea
   
    # For AFL instrumentation detection
    afl_hash = -1
   
    # Track seen constants to avoid double counting within basic block
    seen_constants = set()
    
    # AFL pattern detection state
    afl_pattern_state = 0  # 0: initial, 1: found fs:0, 2: found add offset, 3: found movsxd
    temp_register = None   # Track which register is used for TLS access
    area_ptr_register = None  # Track which register holds AFL area pointer
   
    # Analyze each instruction in the block
    while current_addr < end_ea:
        ins_num += 1
       
        # Get instruction information
        instruction_line = idc.generate_disasm_line(current_addr, 0)
        mnemonic = get_base_mnemonic(current_addr)
       
        # Enhanced AFL instrumentation detection (only if check_afl is True)
        if check_afl and afl_hash == -1:  # Only detect if not already found
            try:
                # Pattern matching for AFL++ instrumentation
                if mnemonic == "mov" and "fs:0" in instruction_line:
                    # Step 1: mov rax, fs:0 (or similar register)
                    temp_register = idc.print_operand(current_addr, 0)
                    afl_pattern_state = 1
                    
                elif (afl_pattern_state == 1 and mnemonic == "add" and 
                      temp_register and temp_register in instruction_line and 
                      "cs:" in instruction_line):
                    # Step 2: add rax, cs:off_XXXXX
                    afl_pattern_state = 2
                    
                elif (afl_pattern_state == 2 and mnemonic == "movsxd" and 
                      temp_register and temp_register in instruction_line):
                    # Step 3: movsxd rcx, dword ptr [rax]
                    afl_pattern_state = 3
                    
                elif (afl_pattern_state == 3 and mnemonic == "mov" and 
                      "[" in instruction_line and "]" in instruction_line):
                    # Step 4: mov rdx, [r14] or similar - get AFL area pointer
                    area_ptr_register = idc.print_operand(current_addr, 0)
                    afl_pattern_state = 4
                    
                elif (afl_pattern_state >= 3 and mnemonic == "xor" and 
                      area_ptr_register is not None):
                    # Step 5: xor rcx, cur_loc - This is where we extract cur_loc!
                    operand1 = idc.print_operand(current_addr, 0)
                    operand2 = idc.print_operand(current_addr, 1)
                    
                    # Check if this is XORing with a constant (cur_loc)
                    if operand2.endswith('h') or operand2.isdigit():
                        # Extract the XOR operand value as cur_loc
                        xor_value = idc.get_operand_value(current_addr, 1)
                        if xor_value != idc.BADADDR and xor_value != 0:
                            afl_hash = xor_value
                            # Reset state after successful detection
                            afl_pattern_state = 0
                            temp_register = None
                            area_ptr_register = None
                            
                # Reset state if pattern is broken
                elif afl_pattern_state > 0:
                    # Allow some flexibility - don't reset immediately
                    # Only reset if we encounter instructions that clearly break the pattern
                    if mnemonic in ["call", "jmp", "ret", "jz", "jnz", "je", "jne"]:
                        afl_pattern_state = 0
                        temp_register = None
                        area_ptr_register = None
                        
            except Exception as e:
                logging.warning(f"Error in AFL pattern detection at {hex(current_addr)}: {e}")
                afl_pattern_state = 0
                temp_register = None
                area_ptr_register = None
       
        # Extract constants from this instruction
        try:
            constants = extract_constants_from_instruction(current_addr, seen_constants, STRING_ADDRS)
            imme_num += constants['numeric']
            string_num += constants['string']
               
        except Exception as e:
            logging.warning(f"Error extracting constants from {hex(current_addr)}: {e}")
       
        # Count instruction types with improved detection
        try:
            # Check for memory operations using enhanced detection
            if is_memory_operation(current_addr, mnemonic):
                mem_num += 1
           
            # Count arithmetic operations using enhanced detection
            if is_arithmetic_operation(current_addr, mnemonic):
                arith_num += 1
               
        except Exception as e:
            logging.warning(f"Error categorizing instruction at {hex(current_addr)}: {e}")
       
        current_addr = idc.next_head(current_addr)
        if current_addr == idc.BADADDR:
            break
    
    # Record this basic block for the function (with AFL info)
    func2bbs[func_name_hash].append((block.start_ea, afl_hash))
    
    # Create basic block node with correct attribute order
    # [imme_num, string_num, mem_num, arith_num, indegree, offspring, betweenness]
    bb_node = BBlock(afl_hash , func_name, func_name_hash, block.start_ea) # if cur_loc is not found then afl_hash == -1
    bb_node.set_attr(imme_num, string_num, mem_num, arith_num, 0.0, 0.0, 0.0)
    bb_node.set_ins_num(ins_num)
    
    return bb_node


def process_function_cfg_complete(func_addr):
    '''Process complete control flow graph for a single function (all blocks, regardless of AFL)'''
    global CFG, addr2node  # Use CFG consistently
    
    try:
        func_obj = idaapi.get_func(func_addr)
        if func_obj is None:
            return
            
        flow_chart = idaapi.FlowChart(func_obj, flags=idaapi.FC_PREDS)
        basic_blocks = list(flow_chart)
        
        if not basic_blocks:
            return
            
        func_name = idc.get_func_name(func_addr) or f"sub_{func_addr:X}"
        func_name_hash = function_name_hash(func_name)
        
        # Process ALL basic blocks in the function
        bb_nodes = {}
        
        for block in basic_blocks:
            # Analyze basic block (don't filter by AFL at this stage)
            bb_node = analyze_basic_block(block, func_name, func_name_hash, check_afl=True)
            bb_nodes[block.start_ea] = bb_node
            
            # Add to global mappings
            addr2node[block.start_ea] = bb_node
            
            # Add node to CFG
            CFG.add_node(bb_node)
        
        # Add ALL edges based on control flow (regardless of AFL instrumentation)
        for block in basic_blocks:
            current_node = bb_nodes.get(block.start_ea)
            if current_node is None:
                continue
                
            # Add edges to ALL successors
            for successor in block.succs():
                successor_node = bb_nodes.get(successor.start_ea)
                if successor_node is not None:
                    CFG.add_edge(current_node, successor_node)
                    
                    # Update location mappings for AFL analysis (only if both blocks have AFL)
                    if (current_node.hash_val != -1 and current_node.hash_val != -2 and
                        successor_node.hash_val != -1 and successor_node.hash_val != -2):
                        location = (current_node.hash_val >> 1) ^ successor_node.hash_val
                        loc2bbs[location].add(current_node.hash_val)
                        loc2bbs[location].add(successor_node.hash_val)
                        loc2functions[location].add(func_name_hash)
                        
    except Exception as e:
        logging.error(f"Error processing function {hex(func_addr)}: {e}")


def get_statistics():
    '''Get comprehensive statistics with percentiles and distribution info'''
    global CFG  # Use CFG consistently
    
    if len(CFG.nodes()) == 0:
        return {}
    
    stats = {
        'num_nodes': len(CFG.nodes()),
        'num_edges': len(CFG.edges()),
        'attributes': {}
    }
    
    for i, attr_name in enumerate(ATTRS):
        values = [node.get_attr()[i] for node in CFG.nodes()]
        values.sort()
        
        n = len(values)
        stats['attributes'][attr_name] = {
            'min': min(values),
            'max': max(values),
            'mean': sum(values) / len(values),
            'median': values[n // 2] if n % 2 == 1 else (values[n // 2 - 1] + values[n // 2]) / 2,
            'p25': values[n // 4],
            'p75': values[3 * n // 4],
            'sum': sum(values),
            'zeros': values.count(0),
            'nonzeros': n - values.count(0)
        }
        
        # Calculate standard deviation
        mean_val = stats['attributes'][attr_name]['mean']
        variance = sum((x - mean_val) ** 2 for x in values) / len(values)
        stats['attributes'][attr_name]['std'] = math.sqrt(variance)
        
        # Distribution info
        stats['attributes'][attr_name]['distribution'] = {
            'unique_values': len(set(values)),
            'sparsity': values.count(0) / n  # Fraction of zero values
        }

    return stats


def save_results():
    '''Save analysis results in multiple formats'''
    global base_name, dir_name, CFG, funchash2name, addr2funcname, func2bbs, CG
    
    print("[+] Saving analysis results...")
    
    # Updated CSV header to match actual attribute order
    # [imme_num, string_num, mem_num, arith_num, indegree, offspring, betweenness]
    csv_path = os.path.join(dir_name, base_name + '_acfg_analysis.csv')
    with open(csv_path, 'w') as f:
        f.write('func_name,func_name_hash,addr,hash_val,imme_num,string_num,mem_num,arith_num,indegree,offspring,betweenness,ins_num\n')
        for node in CFG.nodes():
            attrs = node.get_attr()
            line = (f"{node.func_name},{node.func_name_hash},{hex(node.addr)},"
                   f"{node.hash_val},{','.join(map(str, attrs))},{node.ins_num}\n")
            f.write(line)
    
    # 2. Save function database as JSON
    function_db = {
        "summary": {
            "binary_name": base_name,
            "total_functions": len(funchash2name),
            "analysis_timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        },
        "functions": {},
        "address_lookup": {}
    }
    
    for func_hash, func_name in funchash2name.items():
        function_db["functions"][str(func_hash)] = {
            "name": func_name,
            "basic_blocks": [
                {"start_ea": hex(bb[0]), "cur_loc": hex(bb[1])}
                for bb in func2bbs.get(func_hash, [])
            ]
        }
    
    for addr, name in addr2funcname.items():
        function_db["address_lookup"][hex(addr)] = name
    
    json_path = os.path.join(dir_name, base_name + '_functions.json')
    with open(json_path, 'w') as f:
        json.dump(function_db, f, indent=2, sort_keys=True)
    
    # 3. Save basic block attributes
    # bb_attrs = {}
    # for node in CFG.nodes():
    #     bb_attrs[hex(node.addr)] = {
    #         'attributes': node.get_attr(),
    #         'ins_count': node.ins_num,
    #         'function': node.func_name
    #     }
    
    # bb_path = os.path.join(dir_name, base_name + '_bb2attributes.json')
    # with open(bb_path, 'w') as f:
    #     json.dump(bb_attrs, f, indent=2)
    
    # Simplified FORMAT
    bb_attrs = {}
    for node in CFG.nodes():
        bb_attrs[str(node.addr)] = node.get_attr()  # Only store attributes array, use decimal key

    bb_path = os.path.join(dir_name, base_name + '_bb2attributes.json')
    with open(bb_path, 'w') as f:
        json.dump(bb_attrs, f, indent=2)

    # save_standardized_attributes()

    # 4. Save location mappings
    loc_funcs = {str(k): list(v) for k, v in loc2functions.items()}
    loc_bbs = {str(k): list(v) for k, v in loc2bbs.items()}
    
    loc_funcs_path = os.path.join(dir_name, base_name + '_loc2functions.json')
    loc_bbs_path = os.path.join(dir_name, base_name + '_loc2bbs.json')
    
    with open(loc_funcs_path, 'w') as f:
        json.dump(loc_funcs, f, indent=2)
    
    with open(loc_bbs_path, 'w') as f:
        json.dump(loc_bbs, f, indent=2)

    # 5. Save NetworkX graph
    graph_path = os.path.join(dir_name, base_name + '_graph.pkl')
    with open(graph_path, 'wb') as f:
        pickle.dump(CG, f, pickle.DEFAULT_PROTOCOL)
    
    # 6. Save statistics
    stats = get_statistics()
    stats_path = os.path.join(dir_name, base_name + '_statistics.json')
    with open(stats_path, 'w') as f:
        json.dump(stats, f, indent=2)
    
    print(f"[+] Results saved to {dir_name}/")
    print(f"    - Main analysis: {base_name}_acfg_analysis.csv")
    print(f"    - Functions DB: {base_name}_functions.json")
    print(f"    - BB attributes: {base_name}_bb2attributes.json")
    print(f"    - NetworkX graph: {base_name}_graph.pkl")
    print(f"    - Statistics: {base_name}_statistics.json")


def main_analysis():
    '''Main analysis pipeline'''
    global bb_cache, addr2funcname, funchash2name, STRING_ADDRS
    
    print("[+] Starting binary analysis...")
    print(f"    Binary: {base_name}")
    print(f"    Address range: {hex(min_addr)} - {hex(max_addr)}")
    
    # Initialize basic block cache
    print("[+] Building basic block cache...")
    bb_cache = BBCache()
    print(f"    Cached {bb_cache.get_cache_size()} basic blocks")
    
    # Process all functions - build COMPLETE graph
    print("[+] Processing functions and building complete CFG...")
    functions = list(idautils.Functions())
    processed_count = 0

    STRING_ADDRS = get_all_ida_strings()
    
    for func_addr in functions:
        func_name = idc.get_func_name(func_addr) or f"sub_{func_addr:X}"
        
        if not function_filter(func_addr):
            continue
        
        addr2funcname[func_addr] = func_name
        funchash2name[function_name_hash(func_name)] = func_name
        
        # Process complete CFG regardless of AFL instrumentation
        process_function_cfg_complete(func_addr)
        processed_count += 1
        
        if processed_count % 100 == 0:
            print(f"    Processed {processed_count} functions...")
    
    print(f"[+] Processed {processed_count} functions")
    print(f"[+] Built complete CFG with {len(CFG.nodes())} nodes and {len(CFG.edges())} edges")
    
    if len(CFG.nodes()) == 0:
        print("[ERROR] No nodes in control flow graph!")
        return False
    
    # Build call graph (separate from CFG)
    build_call_graph()
    
    # Calculate graph metrics on the COMPLETE CFG
    print("[+] Calculating graph metrics on complete CFG...")
    set_graph_metrics()
    
    # Validate attributes before processing
    if not validate_attributes():
        print("[ERROR] Attribute validation failed!")
        return False

    # standardization of attributes
    standardize_attributes_max_norm()

    # Apply PageRank for attribute propagation on complete CFG
    print("[+] Applying PageRank algorithm on complete CFG...")
    # attributed_pagerank(iterations=32)
    attributed_pagerank_convergence(iterations=32)
    # standardization of attributes after apagerank may distort the relative importance that PageRank established

    # Final validation
    if not validate_attributes():
        print("[ERROR] Final validation failed!")
        return False

    return True


def run_afl_analysis():
    """Run AFL location extraction analysis"""
    try:
        extractor = AFLLocationExtractor()
        success = extractor.run_analysis()
        
        if success:
            print('[+] AFL location extraction completed successfully!')
            return True
        else:
            print('[!] AFL location extraction completed but no instrumentation found')
            return False
        
    except Exception as e:
        print(f"[ERROR] AFL analysis failed: {e}")
        logging.error(f"Main analysis failed: {e}", exc_info=True)
        return False


def main():
    '''Main entry point'''
    try:
        time_start = time.time()
        
        # Run main analysis
        success = main_analysis()
        if not success:
            print("[ERROR] main Analysis failed!")
            return

        # Run AFL location analysis
        afl_success = run_afl_analysis()
        if not afl_success:
            print("[ERROR] main Analysis failed!")
            return
        
        # Save results
        save_results()
        
        # Print final statistics
        stats = get_statistics()
        print("\n[+] Analysis Summary:")
        print(f"    Total nodes: {stats['num_nodes']}")
        print(f"    Total edges: {stats['num_edges']}")
        print("    Attribute ranges:")
        
        attr_names = ['imme_num', 'string_num', 'mem_num', 'arith_num', 
                     'indegree', 'offspring', 'betweenness']
        
        for attr_name in attr_names:
            if attr_name in stats['attributes']:
                attr_stats = stats['attributes'][attr_name]
                print(f"      {attr_name}: {attr_stats['min']:.2f} - {attr_stats['max']:.2f} (mean: {attr_stats['mean']:.2f})")
        
        print("\n[+] Binary analysis completed successfully!")

        time_end = time.time()
        print('Extraction Time: {} minutes'.format((time_end - time_start) / 60))

    except Exception as e:
        print(f"[ERROR] Analysis failed with exception: {e}")
        logging.error(f"Main analysis failed: {e}", exc_info=True)


if __name__ == '__main__':
    main()
    print("\n[+] ACFG extraction finished!")
