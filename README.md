# Prototype of FunAFL based on American Fuzzy Lop plus plus (AFL++)

> FunAFL based on AFL++ version: v4.31c

Release version: [4.31c](https://github.com/AFLplusplus/AFLplusplus/releases)

GitHub version: 4.31c

Repository:
[https://github.com/AFLplusplus/AFLplusplus](https://github.com/AFLplusplus/AFLplusplus)

## Building and installing AFL++

prepare the environment and build the fuzzer 
```shell
# install dependencies before compile the FunAFL
./dependencies_install.sh -alt

# compile fuzzer
make clean
time make -j source-only
```

## Static analysis
run the IDAPro scripts `static/acg_extract.py` and `static/loc2bbs_funtions.py` in IDAPro to complete static analysis

> version tested: IDAPro=7.7, Python=3.8

## Running evaluation


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
