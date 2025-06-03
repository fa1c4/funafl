FUNC_HIT_SHM_ID=$(ipcmk -M $((262144 * 4)))
export __AFL_FUNC_HIT_SHM_ID=$(echo $FUNC_HIT_SHM_ID | awk '{print $NF}')