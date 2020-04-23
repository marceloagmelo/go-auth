#!/usr/bin/env bash

# Tabela
echo "Criando a tabela mensagem..."
mysql -h localhost -u root -p -D ${MYSQL_DATABASE} << EOF
use goauthdb;
CREATE TABLE usuario (
id INTEGER UNSIGNED NOT NULL AUTO_INCREMENT,
login VARCHAR(20), senha VARCHAR(100),
email VARCHAR(255), status INTEGER,
PRIMARY KEY (id)
);
EOF

