import os
import sys
import json
import math
import pickle
import signal
import networkx as nx
from copy import deepcopy
from collections import defaultdict
import logging
import time
from pathlib import Path
import subprocess

import custom_mutators.dyn_update.utils as ut
sys.modules['utils'] = ut


# Setup logging
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

if logger.hasHandlers():
    logger.handlers.clear()

handler = logging.StreamHandler(sys.stderr)
formatter = logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

'''
get the paths of files
'''
aicfg_dir = os.environ['FUN_AICFG_DIR']
target_name = os.environ['TARGET_NAME']
afl_pid = None

'''
set constant parameters
'''
# set 0 to disable the attributes, e.g. 1101111 to disable 3rd attribute
base_exp = 1
wl_time = 1
attrs_mask = '1111111' # enable all attributes
partition_wl_graph = ut.parameters["partition_wl_graph"]
function_count_lower = ut.parameters["function_count_lower"]
attributes_num = ut.parameters["attributes_num"]
wl_time_base = ut.parameters["wl_time_base"]
update_interval = ut.parameters.get("update_interval", 4096)  # Make configurable
update_interval_hours = ut.parameters.get("update_interval_hours", 1)  # Default 1 hour
update_interval_seconds = update_interval_hours * 3600  # Convert to seconds

'''
init global variables
'''
CG = nx.DiGraph()
hash2func_node = {}
function2count = defaultdict(dict)
call_count = 0
last_update_time = 0
update_lock = False  # Simple lock to prevent concurrent updates


'''
Helper function to find AFL process PID
'''
def find_afl_pid():
    """Find AFL++ process PID by searching for afl-fuzz process"""
    try:
        # Try to find afl-fuzz process
        result = subprocess.run(['pgrep', '-f', 'afl-fuzz'], 
                              capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            pids = result.stdout.strip().split('\n')
            if pids and pids[0]:
                return int(pids[0])
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, ValueError) as e:
        logger.warning(f"[aicfg_flow] Failed to find AFL PID automatically: {e}")
    return None

'''
Signal AFL process to reload attributes
'''
def signal_afl_update_aicfg():
    """Send SIGUSR1 to AFL process to trigger attribute reload"""
    global afl_pid
    
    assert afl_pid is not None, 'assigned afl_pid error'
    
    if afl_pid:
        try:
            os.kill(afl_pid, signal.SIGUSR1)
            return True
        except (OSError, ProcessLookupError) as e:
            logger.error(f"[aicfg_flow] Failed to signal AFL process {afl_pid}: {e}")
    else:
        logger.error("Could not find AFL process PID")
    
    return False

'''
Atomic file operations for safe updates
'''
def atomic_write_json(data, filepath):
    """Atomically write JSON data to file using temporary file + rename"""
    temp_filepath = filepath + '.tmp'
    try:
        with open(temp_filepath, 'w') as fw:
            json.dump(data, fw, indent=4)
        os.rename(temp_filepath, filepath)
        return True
    except Exception as e:
        logger.error(f"[aicfg_flow] Failed to write {filepath}: {e}")
        # Clean up temp file if it exists
        if os.path.exists(temp_filepath):
            os.remove(temp_filepath)
        return False


'''
sum up the attributes of the nodes in the graph 
'''
def get_sum_of_attributes():
    global CG
    if not CG.nodes():
        return [0] * attributes_num
    
    res = list(CG.nodes())[0].get_attr()
    for i, node in enumerate(CG.nodes()):
        if i != 0:
            cur_attr = node.get_attr()
            res = ut.list_add(res, cur_attr)
    
    return res

'''
get the range of the attributes of the nodes in the graph
'''
def number_range():
    global CG
    if not CG.nodes():
        logger.warning("[aicfg_flow] No nodes in graph for number_range calculation")
        return

    attributes, attributes_sum = [], []
    for node in CG.nodes():
        attributes.append(node.get_attr())
        attributes_sum = ut.list_add(attributes_sum, node.get_attr())
    
    output_name = os.path.join(aicfg_dir, 'attributes_sum.json')
    if atomic_write_json(attributes_sum, output_name):
        logger.info(f'Saved {output_name}')
    

'''
subgraph
'''
def wl_subgraph(times=1):
    global CG, hash2func_node
    if not CG.nodes():
        logger.warning("[aicfg_flow] Empty graph, skipping WL subgraph")
        return

    for _ in range(times):
        new_CG = deepcopy(CG)
        new_hash2func_node = {}
        for node in new_CG.nodes():
            new_hash2func_node[node.addr] = node
        
        node2node = {}
        for hash_val in hash2func_node:
            node2node[hash2func_node[hash_val]] = new_hash2func_node[hash_val]

        for node in CG.nodes():
            if node not in node2node:
                continue

            cur_attr = node.get_attr()
            cycle_nodes = []
            for temp_cycle_node in CG.predecessors(node):
                cycle_nodes.append(temp_cycle_node)
            for temp_cycle_node in CG.successors(node):
                cycle_nodes.append(temp_cycle_node)
            cycle_num = len(cycle_nodes)
            if cycle_num == 0:
                continue

            attributes = []
            for cycle_node in cycle_nodes:
                attributes.append(cycle_node.get_attr())
            sum_of_attributes = ut.sum_of_lists(attributes)
            average_of_attributes = ut.list_parameter_multiply(sum_of_attributes, 1.0 / cycle_num)
            new_attributes1 = ut.list_parameter_multiply(average_of_attributes, partition_wl_graph)
            new_attributes2 = ut.list_parameter_multiply(cur_attr, 1 - partition_wl_graph)
            new_attributes = ut.list_add(new_attributes1, new_attributes2)
            node2node[node].set_attr_by_list(new_attributes)
    
        CG = new_CG
        hash2func_node = new_hash2func_node


'''
exponential decay function
'''
def get_count_score(count):
    return base_exp ** count


'''
standardize the attributes of the nodes in the graph
'''
def standardization(average_v, std_v):
    for node in CG.nodes():
        attr = node.get_attr()
        new_attr = []
        for i, v in enumerate(attr):
            if v != 0:
                new_attr.append((v - average_v[i]) / std_v[i])
            else:
                new_attr.append(v)
        
        node.set_attr_by_list(new_attr)


'''
data feature
'''
def get_data_feature():
    global CG 
    if not CG.nodes():
        logger.warning("No nodes for data feature calculation")
        return {
            'mmax': [0] * attributes_num,
            'mmin': [0] * attributes_num,
            'ssum': [0] * attributes_num,
            'aaverage': [0] * attributes_num,
            'ssquare': [0] * attributes_num
        }

    max_value, min_value, sum_value, average_value = [], [], [], []
    square_average_value, s_square, square = [], [], []
    cg_cnt = len(CG.nodes())

    for i, node in enumerate(CG.nodes()):
        attrs = node.get_attr()
        if i == 0:
            max_value = deepcopy(attrs)
            min_value = deepcopy(attrs)
            sum_value = deepcopy(attrs)
            s_square = ut.list_square(attrs)
        else:
            s_square = ut.list_add(s_square, ut.list_square(attrs))
            for j, attr in enumerate(attrs):
                if attr > max_value[j]:
                    max_value[j] = attr
                if attr < min_value[j]:
                    min_value[j] = attr
                sum_value[j] = sum_value[j] + attr
    
    for p, value in enumerate(sum_value):
        average_value.append(value / float(cg_cnt))
        square_average_value.append(s_square[p] / float(cg_cnt))
    
    for p, value in enumerate(average_value):
        variance = max(0, square_average_value[p] - average_value[p] ** 2)
        square.append(math.sqrt(variance))

    return {
        'mmax': max_value,
        'mmin': min_value,
        'ssum': sum_value,
        'aaverage': average_value,
        'ssquare': square
    }


'''
define normalization function with attrs_mask
'''
def normalization_max_min_range(start=None, end=None):
    global CG, attrs_mask
    
    if start is None:
        start = [0] * attributes_num
    if end is None:
        end = [100] * attributes_num

    # get the max and min values of the attributes
    max_value, min_value = [], []
    for i, node in enumerate(CG.nodes()):
        attrs = node.get_attr()
        if i == 0:
            max_value = deepcopy(attrs)
            min_value = deepcopy(attrs)
        else:
            for j, attr in enumerate(attrs):
                if attr > max_value[j]:
                    max_value[j] = attr
                if attr < min_value[j]:
                    min_value[j] = attr

    # normalize the attributes
    for node in CG.nodes():
        attrs = node.get_attr()
        new_attrs = []
        for j, attr in enumerate(attrs):
            div = max_value[j] - min_value[j]
            if div == 0: 
                div = 1
            # masked then set the attribute to 0.0
            if attrs_mask[j] == '0':
                new_attrs.append(0.0)
            else:
                new_attrs.append(start[j] + (end[j] - start[j]) * ((attr - min_value[j]) / div))
        
        node.set_attr_by_list(new_attrs)


'''
write attribtues to file
'''
def write_graph_attributes(tail='_cg.pkl'):
    global aicfg_dir, target_name
    output_name = aicfg_dir + os.sep + target_name + tail
    title = 'func_name,cmp_num,mem_num,ins_num,bb_num,offspring_reciprocal,betweeness,retain1,retain2,retain3' + '\n'
    with open(output_name, 'w') as fw:
        fw.write(title)
        for node in CG.nodes():
            func_name = node.name
            cmp_num, mem_num, ins_num, bb_num, offspring_reciprocal, betweeness, retain1, retain2, retain3 = node.get_attr()
            line = f'{func_name},{cmp_num},{mem_num},{ins_num},{bb_num},{offspring_reciprocal},{betweeness},{retain1},{retain2},{retain3}' + '\n'
            fw.write(line)


def write_function2attributes(tail='_function2attributes.json'):
    global aicfg_dir, target_name
    function2attributes = defaultdict(dict) # {func_name_hash: {bb_hash: [cmp_num, mem_num, ins_num, imme]}}
    for node in CG.nodes():
        function2attributes[node.func_name_hash][node.hash_val] = node.get_attr()

    output_name = aicfg_dir + os.sep + target_name + tail
    with open(output_name, 'w') as fw:
        json.dump(function2attributes, fw, indent=4)
    

def write_bb2attributes(tail='_bb2attributes.json'):
    global aicfg_dir, target_name
    bb2attributes = defaultdict(list) # {bb_addr: [cmp_num, mem_num, ins_num, imme]}
    for node in CG.nodes():
        bb2attributes[node.addr] = node.get_attr()
    
    output_name = aicfg_dir + os.sep + target_name + tail
    if atomic_write_json(bb2attributes, output_name):
        logger.info(f'Saved {output_name}')
        return True
    return False

'''
reconstruct graph
'''
def read_function2count_data(input_name):
    bbs_hit = {}
    max_function_count = 1
    with open(input_name, 'r') as fr:
        for data in fr:
            key, value = map(int, data.strip().split(':'))
            bbs_hit[key] = value
            max_function_count = max(max_function_count, value)
    
    return bbs_hit, max_function_count


def reconstruct_graph():
    global aicfg_dir, target_name, base_exp, CG, hash2func_node
    # Try dynamic version first, then fall back to static
    cg_name_dynamic = os.path.join(aicfg_dir, target_name + '_cg_dynamic.pkl')
    cg_name_static = os.path.join(aicfg_dir, target_name + '_cg.pkl')
    cg_name = cg_name_dynamic if os.path.exists(cg_name_dynamic) else cg_name_static
    if not os.path.exists(cg_name):
        logger.error(f"[aicfg_flow] No graph file found: {cg_name}")
        return False
    
    # read the graph from file
    CG = pickle.load(open(cg_name, 'rb'))
    for node in CG.nodes():
        hash2func_node[node.addr] = node

    data_feature = get_data_feature()
    input_name = os.path.join(aicfg_dir, target_name + '_function2count.txt') # need afl-fuzz to write shm data to txt
    bbs_hit, max_function_count = read_function2count_data(input_name)
    base_exp = function_count_lower ** (1.0 / max_function_count)

    # number_range()
    for node in CG.nodes():
        if node.addr in bbs_hit:
            count = bbs_hit[node.addr]
            new_attr = ut.list_parameter_multiply(node.get_attr(), get_count_score(count))
            node.set_attr_by_list(new_attr)
    
    normalization_max_min_range(data_feature['mmin'], data_feature['mmax'])
    return True


def keep_average(avg1, avg2):
    global CG, attributes_num
    avg_ratio = []

    for i in range(attributes_num):
        avg_ratio.append(avg1[i] / avg2[i])
    
    for node in CG.nodes():
        attrs = node.get_attr()
        new_attrs = []
        for i, attr in enumerate(attrs):
            if i >= attributes_num:
                new_attrs.append(0)
                continue
            
            new_attrs.append(attr * avg_ratio[i])
        
        node.set_attr_by_list(new_attrs)

def post_run():
    '''
    Called after each time the execution of the target program by AFL++
    '''
    # global wl_time, CG, call_count, update_lock, update_interval, wl_time_base
    global wl_time, CG, call_count, update_lock, last_update_time, update_interval_seconds, wl_time_base

    # [path 1] execute dynamic adjustment every 1000 calls
    # call_count += 1
    # if call_count < update_interval:
    #     return

    # [path 2] Check if enough time has passed since last update
    current_time = time.time()
    time_since_last_update = current_time - last_update_time
    if time_since_last_update < update_interval_seconds:
        return

    # Prevent concurrent updates
    if update_lock:
        logger.debug("[aicfg_flow] Update already in progress, skipping")
        return
    update_lock = True

    try:
        logger.info(f"[aicfg_flow] Starting dynamic update at call {call_count}")
        
        # Reconstruct graph
        if not reconstruct_graph():
            logger.error("[aicfg_flow] Failed to reconstruct graph")
            return
        
        nodes_num = len(list(CG.nodes()))
        if nodes_num == 0:
            logger.warning("[aicfg_flow] Empty graph after reconstruction")
            return
            
        # Calculate WL time
        assert wl_time_base != 0, 'wl_time_base is 0'
        if int(nodes_num / wl_time_base) > 1 and wl_time <= 1:
            wl_time = int(nodes_num / wl_time_base)
        
        logger.info(f'[aicfg_flow] nodes_num: {nodes_num}, wl_time: {wl_time}, wl_time_base: {wl_time_base}')

        # Apply WL subgraph
        wl_subgraph(wl_time)
        
        # Final normalization
        attrs_append_num = attributes_num + 2
        normalization_max_min_range([0] * attrs_append_num, [100] * attrs_append_num)
        
        # Write updated attributes
        if write_bb2attributes('_bb2attributes_dynamic.json'):
            logger.info("[aicfg_flow] Successfully wrote dynamic attributes")
            
            # Save updated graph
            cg_file = os.path.join(aicfg_dir, target_name + '_cg_dynamic.pkl')
            try:
                nx.write_gpickle(CG, cg_file)
                logger.info(f"[aicfg_flow] Saved updated graph to {cg_file}")
            except Exception as e:
                logger.error(f"[aicfg_flow] Failed to save graph: {e}")
            
            # Signal AFL to reload
            if signal_afl_update_aicfg():
                logger.info("[aicfg_flow] Successfully signaled AFL for attribute reload")
            else:
                logger.warning("[aicfg_flow] Failed to signal AFL for attribute reload")
        else:
            logger.error("[aicfg_flow] Failed to write dynamic attributes")
    
    except Exception as e:
        logger.error(f"[aicfg_flow] Error in post_run: {e}")

    # finally
    # call_count = 0
    update_lock = False
    last_update_time = current_time


'''
entry of fuzz python module
'''
def init(seed):
    global afl_pid, last_update_time
    logger.info('[aicfg_flow] Initializing AICFG dynamic adjustment module...')
    logger.info(f'[aicfg_flow] aicfg_dir: {aicfg_dir}')
    logger.info(f'[aicfg_flow] attrs_mask: {attrs_mask}')
    logger.info(f'[aicfg_flow] target_name: {target_name}')
    logger.info(f'[aicfg_flow] update_interval: {update_interval}')
    
    # init last update time at the beginning
    last_update_time = time.time()

    # Try to get AFL PID for signaling
    if not afl_pid:
        afl_pid = find_afl_pid()
        if afl_pid:
            logger.info(f'[aicfg_flow] Found AFL PID: {afl_pid}')
        else:
            logger.warning('[aicfg_flow] Could not find AFL PID - signaling may not work')
    
    dynamic_attr_file = os.path.join(aicfg_dir, f"{target_name}_bb2attributes_dynamic.json")
    if os.path.exists(dynamic_attr_file):
        os.remove(dynamic_attr_file)
        logger.info(f"[aicfg_flow] Removed old dynamic attribute file: {dynamic_attr_file}")

    # Validate required directories and files
    if not os.path.exists(aicfg_dir):
        logger.error(f"[aicfg_flow] AICFG directory does not exist: {aicfg_dir}")
        return False
        
    return True
    
def deinit():
    logger.info('AICFG dynamic adjustment module shutting down')
    
    # Final cleanup - save any pending updates
    # if call_count > 0:
    current_time = time.time()
    time_since_last_update = current_time - last_update_time
    if time_since_last_update > 256:
        logger.info("Performing final attribute update before shutdown")
        post_run()
