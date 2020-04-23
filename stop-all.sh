#!/usr/bin/env bash

source setenv.sh

# Mysql
echo "Finalizando o mysql..."
docker rm -f $MYSQL_HOSTNAME

# Message API
echo "Finalizando o $APP_NAME..."
docker rm -f $APP_NAME

# Remover rede
echo "Removendo a rede $DOCKER_NETWORK..."
docker network rm $DOCKER_NETWORK
