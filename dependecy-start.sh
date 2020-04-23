#!/usr/bin/env bash

source setenv.sh

# Criar rede
echo "Criando a rede $DOCKER_NETWORK..."
docker network ls | grep $DOCKER_NETWORK
if [ "$?" != 0 ]; then
   docker network create $DOCKER_NETWORK
fi

# Mysql
echo "Subindo o mysql..."
docker run -d --name mysqldb --network $DOCKER_NETWORK  \
-p 3306:3306 \
-e MYSQL_USER=${MYSQL_USER} \
-e MYSQL_PASSWORD=${MYSQL_PASSWORD} \
-e MYSQL_ROOT_PASSWORD=${MYSQL_ROOT_PASSWORD} \
-e MYSQL_DATABASE=${MYSQL_DATABASE} \
mysql:5.7

# Listando os containers
docker ps
