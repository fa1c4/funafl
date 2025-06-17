import os
import re

log_dir = "../test"
loc_pattern = re.compile(r"loc=(0x[0-9a-fA-F]+)")

loc_set = set()

filepath = log_dir + os.sep + 'bloaty_log'

try:
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            match = loc_pattern.search(line)
            if match:
                loc_set.add(match.group(1))  # add loc
except Exception as e:
    print(f"Error reading {filepath}: {e}")

for loc in sorted(loc_set):
    print(loc)

print("length of loc not found:", len(loc_set))
