echo core | sudo tee /proc/sys/kernel/core_pattern
ulimit -c unlimited

# [1] set the path where to find module
# export PYTHONPATH=/home/fa1c4/Desktop/funafl/custom_mutators/dyn_update
# [2] set the module name without ".py" suffix
# export AFL_PYTHON_MODULE=aicfg_flow
# [3] set the aicfg and target_name environment 
# [4] set test command

export PYTHONPATH=/home/fa1c4/Desktop/funafl

export AFL_PYTHON_MODULE=custom_mutators.dyn_update.aicfg_flow

# target: zlib
export TARGET_NAME=zlib_uncompress_fuzzer

# export FUN_AICFG_DIR=/home/fa1c4/Desktop/aflpp_benchmarks/zlib/aicfg
# ../afl-fuzz -m none -i /home/fa1c4/Desktop/aflpp_benchmarks/zlib/seeds -o /home/fa1c4/Desktop/aflpp_benchmarks/zlib/out -- /home/fa1c4/Desktop/aflpp_benchmarks/zlib/zlib_uncompress_fuzzer
# ../afl-fuzz -m none -i /home/fa1c4/Desktop/aflpp_benchmarks/zlib/seeds -o /home/fa1c4/Desktop/aflpp_benchmarks/zlib/out -- /home/fa1c4/Desktop/aflpp_benchmarks/zlib/zlib_uncompress_fuzzer 2>&1 | tee funlog
# cmplog test
export FUN_AICFG_DIR=/home/fa1c4/Desktop/benchmarks_src/zlib/aicfg
../afl-fuzz -m none -i ../../aflpp_benchmarks/zlib/seeds -o ../../aflpp_benchmarks/zlib/out -c /home/fa1c4/Desktop/benchmarks_src/zlib_cmplog/zlib_uncompress_fuzzer -- /home/fa1c4/Desktop/benchmarks_src/zlib/zlib_uncompress_fuzzer @@


# target: lcms
# export FUN_AICFG_DIR=/home/fa1c4/Desktop/funafl-bench/lcms/aicfg
# export TARGET_NAME=cms_transform_fuzzer

# ../afl-fuzz -m none -i /home/fa1c4/Desktop/funafl-bench/lcms/seeds -o /home/fa1c4/Desktop/funafl-bench/lcms/out -- /home/fa1c4/Desktop/funafl-bench/lcms/cms_transform_fuzzer
