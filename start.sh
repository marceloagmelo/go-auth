#!/usr/bin/env bash

source setenv.sh

# Verificar rede
echo "Verificando se existe a rede $DOCKER_NETWORK..."
docker network ls | grep $DOCKER_NETWORK
if [ "$?" != 0 ]; then
   echo "Rede $DOCKER_NETWORK não existe!"
   exit 0
fi

# Aplicação
echo "Subindo o $APP_NAME..."
docker run -d --name $APP_NAME --network $DOCKER_NETWORK \
-p 8181:8080 \
-e MYSQL_USER=${MYSQL_USER} \
-e MYSQL_PASSWORD=${MYSQL_PASSWORD} \
-e MYSQL_HOSTNAME=${MYSQL_HOSTNAME} \
-e MYSQL_DATABASE=${MYSQL_DATABASE} \
-e MYSQL_PORT=${MYSQL_PORT} \
-e TZ=America/Sao_Paulo \
marceloagmelo/$APP_NAME

# Listando os containers
docker ps
