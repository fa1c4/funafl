#!/bin/sh

. ./test-pre.sh

OS=$(uname -s)

AFL_COMPILER=afl-clang-fast
$ECHO "$BLUE[*] Testing: afl-fuzz"
 test -e ../${AFL_COMPILER} -a -e ../afl-showmap -a -e ../afl-fuzz && {
   # now we want to be sure that afl-fuzz is working
   # make sure crash reporter is disabled on Mac OS X
   (test "$OS" = "Darwin" && test $(launchctl list 2>/dev/null | grep -q '\.ReportCrash$') && {
    $ECHO "$RED[!] we cannot run afl-fuzz with enabled crash reporter. Run 'sudo sh afl-system-config'.$RESET"
    true
   }) || {
      echo "funafl test error log\n" > errors && {
      TARGET=zlib
      $ECHO "$GREY[*] running afl-fuzz for ${AFL_COMPILER}, this will take approx 10 seconds"
      {
        echo "[+] Testing: ../afl-fuzz -V07 -m ${MEM_LIMIT} -i ../../aflpp_benchmarks/${TARGET}/seeds -o ../../aflpp_benchmarks/${TARGET}/out -- ../../aflpp_benchmarks/${TARGET}/zlib_uncompress_fuzzer" >> errors
        ../afl-fuzz -V07 -m ${MEM_LIMIT} -i ../../aflpp_benchmarks/${TARGET}/seeds -o ../../aflpp_benchmarks/${TARGET}/out -- ../../aflpp_benchmarks/${TARGET}/zlib_uncompress_fuzzer >>errors 2>&1
      } || {
        $ECHO "$RED[+] afl-fuzz is not running correctly with ${TARGET}"
      }
      test -n "$( ls ../../aflpp_benchmarks/zlib/out/default/queue/id:000002* 2>/dev/null )" && {
        $ECHO "$GREEN[+] afl-fuzz is working correctly with ${TARGET}"
      }
    } && {
      TARGET=re2
      $ECHO "$GREY[*] running afl-fuzz for ${AFL_COMPILER}, this will take approx 10 seconds"
      {
        echo "[+] Testing: ../afl-fuzz -V07 -m ${MEM_LIMIT} -o ../../aflpp_benchmarks/${TARGET}/out -- ../../aflpp_benchmarks/${TARGET}/fuzzer" >> errors
        ../afl-fuzz -V07 -m ${MEM_LIMIT} -o ../../aflpp_benchmarks/${TARGET}/out -- ../../aflpp_benchmarks/${TARGET}/fuzzer >>errors 2>&1
      } || {
        $ECHO "$RED[+] afl-fuzz is not running correctly with ${TARGET}"
      }
      test -n "$( ls ../../aflpp_benchmarks/re2/out/default/queue/id:000002* 2>/dev/null )" && {
        $ECHO "$GREEN[+] afl-fuzz is working correctly with ${TARGET}"
      }
    }
   } || {
    $ECHO "$RED[!] afl-fuzz is not working correctly with ${AFL_COMPILER}"
    CODE=1
   }
 } || {
   $ECHO "$YELLOW[-] afl is not compiled, cannot test"
   INCOMPLETE=1
 }

. ./test-post.sh
