export SSHPASS='zhangj25'
REMOTE_USER='zhangj25'
REMOTE_HOST='192.168.5.122'
REMOTE_CMD="cd ~/dcqcn-tuning/RDMAexample && git pull $*"

sshpass -e ssh -o StrictHostKeyChecking=accept-new \
"${REMOTE_USER}@${REMOTE_HOST}" "${REMOTE_CMD}"