# funafl

funafl fuzzer instance that has the following config active for all benchmarks (align with AFL++ in fuzzbench):
  - PCGUARD instrumentation 
  - cmplog feature
  - dict2file feature
  - "fast" power schedule
  - persistent mode + shared memory test cases

Repository: [https://github.com/fa1c4/funafl.git](https://github.com/fa1c4/funafl.git)

[builder.Dockerfile](builder.Dockerfile)
[fuzzer.py](fuzzer.py)
[runner.Dockerfile](runner.Dockerfile)
