# API de Autenticação de Usuáro usando Golang e MySQL

Este é um serviço de acesso aos dados do usuário no banco **MySQL**. Este serviço possuem algumas funcionalidades.

- [Listar Usuarios](#listar-usuarios)
- [Adicionar Usuário](#adicionar-usuario)
- [Atualizar Usuário](#atualizar-usuario)
- [login Usuário](#readicionar-usuario)
- [Apagar Usuário](#apagar-usuario)
- [Listar por Status do Usuário](#listar-por-status-do-usuario)
- [Recuperar um Usuário](#recuperar-um-usuario)

----


# Instalação

```
go get -v github.com/marceloagmelo/go-auth
```
```
cd go-auth
```

## Build da Aplicação

```
./image-build.sh
```

## Iniciar as Aplicações de Dependências
```
./dependecy-start.sh
```

## Preparar o MySQL

```
docker  exec -it mysqldb bash -c "mysql -u root -p"
```
- Criar a tabela
	> use goauthdb;
	
	> CREATE TABLE usuario (
id INTEGER UNSIGNED NOT NULL AUTO_INCREMENT,
login VARCHAR(20), senha VARCHAR(100),
email VARCHAR(255), status INTEGER,
PRIMARY KEY (id)
);

## Iniciar a Aplicação Message API
```
./start.sh
```
```
http://localhost:8181/go-auth/api/v1/health
```

## Finalizar a Aplicação Message API
```
./stop.sh
```

## Finalizar a Todas as Aplicações
```
./stop-all.sh
```

# Serviços
Lista dos serviços disponíveis:

### Listar Usuários
[http://localhost:8181/go-auth/api/v1/Usuarios](http://localhost:8181/go-auth/api/v1/Usuarios)

### Adicionar Usuário
```
curl -v -d '{"login":"marcelo", "senha":"password", "email": "xpto@gmail.com}' -H "Content-Type: application/json" -X POST http://localhost:8181/go-auth/api/v1/usuario/adicionar
```

### Atualizar Usuário
```
curl -v -d '{"id":1, "login":"marcelo", "senha":"password", "email": "xpto@gmail.com, "status":2}' -H "Content-Type: application/json" -X PUT http://localhost:8181/go-auth/api/v1/usuario/atualizar
```

### login Usuário
```
curl -v -d '{"login":"marcelo", "senha":"password"}' -H "Content-Type: application/json" -X POST http://localhost:8181/go-auth/api/v1/usuario/login
```

### Apagar Usuário
```
curl -H "Content-Type: application/json" -X DELETE http://localhost:8181/go-auth/api/v1/usuario/apagar/1
```

### Listar por Status do Usuário
[http://localhost:8181/go-auth/api/v1/usuario/status/2](http://localhost:8181/go-auth/api/v1/usuario/status/1)

### Recuperar um Usuário
[http://localhost:8181/go-auth/api/v1/usuario/1](http://localhost:8181/go-auth/api/v1/usuario/1)