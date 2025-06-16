# Prototype of FunAFL based on American Fuzzy Lop plus plus (AFL++)

> FunAFL based on AFL++ version: v4.31c

Release version: [4.31c](https://github.com/AFLplusplus/AFLplusplus/releases)

GitHub version: 4.31c

Repository:
[https://github.com/AFLplusplus/AFLplusplus](https://github.com/AFLplusplus/AFLplusplus)

## Building and installing AFL++

prepare the environment and build the fuzzer 

> dependencies: llvm-15 clang-15

```shell
# install dependencies before compile the FunAFL
./dependencies_install.sh --install
./dependencies_install.sh --alt

# compile fuzzer
make clean
time make -j source-only
# afl-fuzz and supporting tools 
# LLVM basic mode, LLVM mode, LLVM LTO mode, gcc_mode should be built successfully
# and ignore Nyx build error
```

## Static analysis
run the IDAPro scripts `static/acg_extract.py` and `static/loc2bbs_funtions.py` in IDAPro to complete static analysis

> version tested: IDAPro=7.7, Python=3.8

## Running evaluation
### FuzzBench
copy the `integration/fuzzbench` to FuzzBench `fuzzbench/fuzzers/funafl` then run the evaluation of funafl 
and completed static analysis and put the results data to `fuzzbench/funzzers/funafl/aicfg`
```shell
git clone https://github.com/google/fuzzbench
cd fuzzbench/fuzzers
mkdir funafl
cp /path/to/funafl/integration/fuzzbench/* ./funafl

cd ../ && make install-dependencies
make presubmit

# require python3 environment
source .venv/bin/activate

PYTHONPATH=. python3 experiment/run_experiment.py \
--experiment-config exper_config.yaml \
--benchmarks zlib_zlib_uncompress_fuzzer \
--experiment-name funexp \
--fuzzers funafl
```


<!-- </details>

## Cite

If you use AFL++ in scientific work, consider citing
[our paper](https://www.usenix.org/conference/woot20/presentation/fioraldi)
presented at WOOT'20:

    Andrea Fioraldi, Dominik Maier, Heiko Eißfeldt, and Marc Heuse. “AFL++: Combining incremental steps of fuzzing research”. In 14th USENIX Workshop on Offensive Technologies (WOOT 20). USENIX Association, Aug. 2020.

<details>

<summary>BibTeX</summary>

  ```bibtex
  @inproceedings {AFLplusplus-Woot20,
  author = {Andrea Fioraldi and Dominik Maier and Heiko Ei{\ss}feldt and Marc Heuse},
  title = {{AFL++}: Combining Incremental Steps of Fuzzing Research},
  booktitle = {14th {USENIX} Workshop on Offensive Technologies ({WOOT} 20)},
  year = {2020},
  publisher = {{USENIX} Association},
  month = aug,
  }
  ```

</details> -->
