#!/usr/bin/env bash

source setenv.sh

echo "Finalizando o $APP_NAME..."
docker rm -f $APP_NAME
