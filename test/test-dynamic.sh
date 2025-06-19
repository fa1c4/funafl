echo core | sudo tee /proc/sys/kernel/core_pattern
ulimit -c unlimited

# set the path where to find module
# export PYTHONPATH=/home/fa1c4/Desktop/funafl/custom_mutators/dyn_update
export PYTHONPATH=/home/fa1c4/Desktop/funafl
# set the module name without ".py" suffix
# export AFL_PYTHON_MODULE=aicfg_flow
export AFL_PYTHON_MODULE=custom_mutators.dyn_update.aicfg_flow

# set the aicfg and target_name environment 
export FUN_AICFG_DIR=/home/fa1c4/Desktop/aflpp_benchmarks/zlib/aicfg
export TARGET_NAME=zlib_uncompress_fuzzer

# afl-fuzz /path/to/program
# test command
# ../afl-fuzz -m none -i /home/fa1c4/Desktop/aflpp_benchmarks/zlib/seeds -o /home/fa1c4/Desktop/aflpp_benchmarks/zlib/out -- /home/fa1c4/Desktop/aflpp_benchmarks/zlib/zlib_uncompress_fuzzer 2>&1 | tee funlog
../afl-fuzz -m none -i /home/fa1c4/Desktop/aflpp_benchmarks/zlib/seeds -o /home/fa1c4/Desktop/aflpp_benchmarks/zlib/out -- /home/fa1c4/Desktop/aflpp_benchmarks/zlib/zlib_uncompress_fuzzer
# /home/fa1c4/Desktop/funafl/afl-fuzz -m none -i /home/fa1c4/Desktop/aflpp_benchmarks/zlib/seeds -o /home/fa1c4/Desktop/aflpp_benchmarks/zlib/out -- /home/fa1c4/Desktop/aflpp_benchmarks/zlib/zlib_uncompress_fuzzer
