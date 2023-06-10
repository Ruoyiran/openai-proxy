#! /usr/bin/env bash

if [ $# -lt 1 ]; then
    echo "Usage: $0 os[darwin, linux]"
    exit 1
fi
os=$1
arch=amd64

BINARY_NAME=azure_openai_proxy
OUTPUT_DIR=output
OUTPUT_BIN_DIR=${OUTPUT_DIR}/bin
START_SCRIPT=./start.sh
STOP_SCRIPT=./stop.sh

rm -rf ${OUTPUT_DIR}
mkdir -p ${OUTPUT_BIN_DIR}

GOOS=$os GOARCH=${arch} go build -o ${OUTPUT_BIN_DIR}/${BINARY_NAME} main.go

if [ $? = 0 ]; then
  cp -v ${START_SCRIPT} ${OUTPUT_DIR}
  cp -v ${STOP_SCRIPT} ${OUTPUT_DIR}
fi

