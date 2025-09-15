#!/bin/bash

set -e
set -u

if [ -e ./firmae.config ]; then
    source ./firmae.config
elif [ -e ../firmae.config ]; then
    source ../firmae.config
else
    echo "Error: Could not find 'firmae.config'!"
    exit 1
fi

if check_number $1; then
    echo "Usage: umount.sh <image ID> <mode>"
    exit 1
fi
IID=${1}
MODE=${2}

# Assign abbreviation based on MODE

if [ "${MODE}" == "run" ]; then
    mode_abbr="run"
elif [[ "${MODE}" == *"staff_base"* ]]; then
    suffix=${MODE#*"staff_base"}
    mode_abbr="sb${suffix}"
elif [[ "${MODE}" == *"staff_state_aware"* ]]; then
    suffix=${MODE#*"staff_state_aware"}
    mode_abbr="ss${suffix}"
elif [[ "${MODE}" == *"triforce"* ]]; then
    suffix=${MODE#*"triforce"}
    mode_abbr="t${suffix}"
elif [[ "${MODE}" == *"aflnet_base"* ]]; then
    suffix=${MODE#*"aflnet_base"}
    mode_abbr="ab${suffix}"
elif [[ "${MODE}" == *"aflnet_state_aware"* ]]; then
    suffix=${MODE#*"aflnet_state_aware"}
    mode_abbr="as${suffix}"
elif [[ "${MODE}" == *"pre_analysis"* ]]; then
    suffix=${MODE#*"pre_analysis"}
    mode_abbr="pa${suffix}"
elif [[ "${MODE}" == *"pre_exp"* ]]; then
    suffix=${MODE#*"pre_exp"}
    mode_abbr="pe${suffix}"
else
    echo "ERROR: Insert mode!"
    exit 1
fi


if check_root; then
    echo "Error: This script requires root privileges!"
    exit 1
fi

echo "----Running----"
WORK_DIR=`get_scratch ${IID} ${mode_abbr}`
IMAGE=`get_fs ${IID} ${mode_abbr}`
IMAGE_DIR=`get_fs_mount ${IID} ${mode_abbr}`

DEVICE=`get_device`

echo "----Unmounting----"
umount "${DEVICE}"

echo "----Disconnecting Device File----"
kpartx -d "${IMAGE}"
losetup -d "${DEVICE}" &>/dev/null
dmsetup remove $(basename "${DEVICE}") &>/dev/null
