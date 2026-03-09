#!/bin/bash
# Usage: ./NotifyReceive.sh [N=<num_hosts>] [F=<flows_per_host>] [extra make vars...]
# Example: ./NotifyReceive.sh N=2 F=3
#
# Forwards all arguments directly to `make run` on the remote receiver.

sleep 3
export SSHPASS=''
REMOTE_USER='zhangj25'
REMOTE_HOST='192.168.5.122'
REMOTE_CMD="cd ~/dcqcn-tuning/RDMAexample && make run $*"

sshpass -e ssh -o StrictHostKeyChecking=accept-new \
  "${REMOTE_USER}@${REMOTE_HOST}" "${REMOTE_CMD}"
