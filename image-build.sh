#!/usr/bin/env bash

source setenv.sh

docker build -t $DOCKER_REGISTRY/go-message-api .
