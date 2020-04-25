package handler

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/marceloagmelo/go-auth/logger"
	"github.com/marceloagmelo/go-auth/models"
	"github.com/marceloagmelo/go-auth/utils"
	"github.com/marceloagmelo/go-auth/variaveis"
	"upper.io/db.v3"
)

type retorno struct {
	Status string `json:"mensagem"`
}

//Health testa conexão com o mysql e rabbitmq
func Health(db db.Database, w http.ResponseWriter, r *http.Request) {
	dataHoraFormatada := variaveis.DataHoraAtual.Format(variaveis.DataFormat)

	var usuarioModel = db.Collection("usuario")

	_, err := models.TodosUsuarios(usuarioModel)
	if err != nil {
		mensagem := fmt.Sprintf("%s: %s", "Erro ao conectar com o banco de dados", err)
		logger.Erro.Println(mensagem)
		respondError(w, http.StatusInternalServerError, mensagem)
		return
	}

	retorno := retorno{}
	retorno.Status = fmt.Sprintf("OK [%v] !", dataHoraFormatada)

	respondJSON(w, http.StatusOK, retorno)
}

//TodosUsuarios listagem de todoos os usuários
func TodosUsuarios(db db.Database, w http.ResponseWriter, r *http.Request) {
	username, password, ok := r.BasicAuth()
	if !ok {
		mensagem := fmt.Sprintf("%s: %v", "HTTP Basic Authentication obrigatório", http.StatusForbidden)
		logger.Erro.Println(mensagem)
		respondError(w, http.StatusInternalServerError, mensagem)
		return
	}

	_, err := getUsuario(db, username, password)
	if err != nil {
		mensagem := fmt.Sprintf("%s", err)
		respondError(w, http.StatusInternalServerError, mensagem)
		return
	}

	var usuarioModel = db.Collection("usuario")

	usuarios, err := models.TodosUsuarios(usuarioModel)
	if err != nil {
		mensagem := fmt.Sprintf("%s: %s", "Erro ao listar todos os usuários", err)
		logger.Erro.Println(mensagem)
		respondError(w, http.StatusInternalServerError, mensagem)
		return
	}

	respondJSON(w, http.StatusOK, usuarios)
}

//Adicionar usuário
func Adicionar(db db.Database, w http.ResponseWriter, r *http.Request) {
	var novoUsuario models.Usuario

	if r.Method == "POST" {
		username, password, ok := r.BasicAuth()
		if !ok {
			mensagem := fmt.Sprintf("%s: %v", "HTTP Basic Authentication obrigatório", http.StatusForbidden)
			logger.Erro.Println(mensagem)
			respondError(w, http.StatusInternalServerError, mensagem)
			return
		}

		_, err := getUsuario(db, username, password)
		if err != nil {
			mensagem := fmt.Sprintf("%s", err)
			respondError(w, http.StatusInternalServerError, mensagem)
			return
		}

		reqBody, err := ioutil.ReadAll(r.Body)
		if err != nil {
			mensagem := fmt.Sprintf("%s: %s", "Adicionando novo usuário no banco de dados", err)
			logger.Erro.Println(mensagem)
			respondError(w, http.StatusInternalServerError, mensagem)
			return
		}

		json.Unmarshal(reqBody, &novoUsuario)

		senhaSum := sha256.Sum256([]byte(novoUsuario.Senha))
		senhaHash := fmt.Sprintf("%X", senhaSum)

		novoUsuario.Login = novoUsuario.Login
		novoUsuario.Senha = string(senhaHash)
		novoUsuario.Status = 1

		if novoUsuario.Login != "" && novoUsuario.Senha != "" && novoUsuario.Email != "" {
			var usuarioModel = db.Collection("usuario")
			var interf models.Metodos

			interf = novoUsuario

			strID, err := interf.Adicionar(usuarioModel)
			if err != nil {
				mensagem := fmt.Sprintf("%s: %s", "Erro ao adicionar o usuário", err)
				respondError(w, http.StatusInternalServerError, mensagem)
				return
			}

			id, err := strconv.Atoi(strID)
			if err != nil {
				if err != nil {
					mensagem := fmt.Sprintf("%s: %s", "Erro ao adicionar o usuário", err)
					logger.Erro.Println(mensagem)
					respondError(w, http.StatusInternalServerError, mensagem)
					return
				}
			}
			novoUsuario.ID = id
		} else {
			mensagem := fmt.Sprint("Login, Senha our Email obrigatórios!")
			logger.Erro.Println(mensagem)

			respondError(w, http.StatusLengthRequired, mensagem)
			return
		}

		respondJSON(w, http.StatusCreated, novoUsuario)
	}
}

//Atualizar atualizar usuário
func Atualizar(db db.Database, w http.ResponseWriter, r *http.Request) {
	var novoUsuario models.Usuario

	if r.Method == "PUT" {
		username, password, ok := r.BasicAuth()
		if !ok {
			mensagem := fmt.Sprintf("%s: %v", "HTTP Basic Authentication obrigatório", http.StatusForbidden)
			logger.Erro.Println(mensagem)
			respondError(w, http.StatusInternalServerError, mensagem)
			return
		}

		_, err := getUsuario(db, username, password)
		if err != nil {
			mensagem := fmt.Sprintf("%s", err)
			respondError(w, http.StatusInternalServerError, mensagem)
			return
		}

		reqBody, err := ioutil.ReadAll(r.Body)
		if err != nil {
			mensagem := fmt.Sprintf("%s: %s", "Erro ao atualizar o usuário", err)
			logger.Erro.Println(mensagem)
		}

		json.Unmarshal(reqBody, &novoUsuario)

		senhaSum := sha256.Sum256([]byte(novoUsuario.Senha + novoUsuario.Login))
		senhaHash := fmt.Sprintf("%X", senhaSum)

		novoUsuario.Senha = string(senhaHash)

		if novoUsuario.ID > 0 && novoUsuario.Login != "" && novoUsuario.Senha != "" && novoUsuario.Email != "" && utils.InBetween(novoUsuario.Status, 1, 2) {
			var usuarioModel = db.Collection("usuario")
			var interf models.Metodos

			interf = novoUsuario

			err := interf.Atualizar(usuarioModel)
			if err != nil {
				mensagem := fmt.Sprintf("%s: %s", "Erro ao atualizar o usuário", err)
				respondError(w, http.StatusInternalServerError, mensagem)
				return
			}
		} else {
			mensagem := fmt.Sprint("Campos obrigatórios!")

			if novoUsuario.ID <= 0 {
				mensagem = fmt.Sprint("ID do usuário menor ou igual a zero!")
			} else if !utils.InBetween(novoUsuario.Status, 1, 2) {
				mensagem = fmt.Sprint("Status diferente de 1 e 2!")
			}
			logger.Erro.Println(mensagem)

			respondError(w, http.StatusLengthRequired, mensagem)
			return
		}

		respondJSON(w, http.StatusOK, novoUsuario)
	}
}

//Logar de usuário
func Logar(db db.Database, w http.ResponseWriter, r *http.Request) {
	var usuario models.Usuario

	if r.Method == "POST" {
		reqBody, err := ioutil.ReadAll(r.Body)
		if err != nil {
			mensagem := fmt.Sprintf("%s: %s", "Erros ao enviar a mensagem", err)
			logger.Erro.Println(mensagem)
		}

		json.Unmarshal(reqBody, &usuario)

		if usuario.Login != "" && usuario.Senha != "" {
			usuarioRetorno, err := getUsuario(db, usuario.Login, usuario.Senha)
			if err != nil {
				mensagem := fmt.Sprintf("%s", err)
				respondError(w, http.StatusInternalServerError, mensagem)
				return
			}
			usuario = usuarioRetorno
		} else {
			mensagem := fmt.Sprint("Login ou Senha obrigatórios!")
			logger.Erro.Println(mensagem)

			respondError(w, http.StatusLengthRequired, mensagem)
			return
		}

		mensagem := fmt.Sprintf("Login do usuário [%v] realizado com sucesso!", usuario.Login)
		logger.Info.Println(mensagem)

		respondJSON(w, http.StatusOK, usuario)
	}
}

//Apagar apagar um usuário
func Apagar(db db.Database, w http.ResponseWriter, r *http.Request) {
	if r.Method == "DELETE" {
		username, password, ok := r.BasicAuth()
		if !ok {
			mensagem := fmt.Sprintf("%s: %v", "HTTP Basic Authentication obrigatório", http.StatusForbidden)
			logger.Erro.Println(mensagem)
			respondError(w, http.StatusInternalServerError, mensagem)
			return
		}

		_, err := getUsuario(db, username, password)
		if err != nil {
			mensagem := fmt.Sprintf("%s", err)
			respondError(w, http.StatusInternalServerError, mensagem)
			return
		}

		vars := mux.Vars(r)
		id, err := strconv.Atoi(vars["id"])
		if err != nil {
			mensagem := fmt.Sprintf("%s: %s", "Erro ID inválido", err)
			logger.Erro.Println(mensagem)

			respondError(w, http.StatusBadRequest, mensagem)
			return
		}

		if id > 0 {
			var usuarioModel = db.Collection("usuario")

			err := models.Apagar(usuarioModel, id)
			if err != nil {
				mensagem := fmt.Sprintf("%s: %s", "Erro ao apagar o usuário", err)
				respondError(w, http.StatusInternalServerError, mensagem)
				return
			}
		} else {
			mensagem := fmt.Sprint("ID do usuário menor ou igual a zero!")
			logger.Erro.Println(mensagem)

			respondError(w, http.StatusLengthRequired, mensagem)
			return

		}
		retorno := retorno{}
		retorno.Status = fmt.Sprintf("Usuário [%v] apagado com sucesso!", id)

		logger.Info.Println(retorno.Status)

		respondJSON(w, http.StatusOK, retorno)
	}
}

//ListarStatus lista de usuários por status
func ListarStatus(db db.Database, w http.ResponseWriter, r *http.Request) {
	username, password, ok := r.BasicAuth()
	if !ok {
		mensagem := fmt.Sprintf("%s: %v", "HTTP Basic Authentication obrigatório", http.StatusForbidden)
		logger.Erro.Println(mensagem)
		respondError(w, http.StatusInternalServerError, mensagem)
		return
	}

	_, err := getUsuario(db, username, password)
	if err != nil {
		mensagem := fmt.Sprintf("%s", err)
		respondError(w, http.StatusInternalServerError, mensagem)
		return
	}

	vars := mux.Vars(r)
	status, err := strconv.Atoi(vars["status"])
	if err != nil {
		mensagem := fmt.Sprintf("%s: %s", "Erro status inválido", err)
		logger.Erro.Println(mensagem)

		respondError(w, http.StatusBadRequest, mensagem)
		return
	}

	if status > 0 {
		if !utils.InBetween(status, 1, 2) {
			mensagem := fmt.Sprint("Status diferente de 1 e 2!")
			respondError(w, http.StatusInternalServerError, mensagem)
			return
		}

		var usuarioModel = db.Collection("usuario")

		usuarios, err := models.ListarStatus(usuarioModel, status)
		if err != nil {
			mensagem := fmt.Sprintf("%s: %s", "Erro ao listar status de usuários", err)
			respondError(w, http.StatusInternalServerError, mensagem)
			return
		}
		respondJSON(w, http.StatusOK, usuarios)
	} else {
		mensagem := fmt.Sprint("Status do usuário menor ou igual a zero!")
		logger.Erro.Println(mensagem)

		respondError(w, http.StatusLengthRequired, mensagem)
		return

	}
}

//UmUsuario recuperar usuário
func UmUsuario(db db.Database, w http.ResponseWriter, r *http.Request) {
	username, password, ok := r.BasicAuth()
	if !ok {
		mensagem := fmt.Sprintf("%s: %v", "HTTP Basic Authentication obrigatório", http.StatusForbidden)
		logger.Erro.Println(mensagem)
		respondError(w, http.StatusInternalServerError, mensagem)
		return
	}

	_, err := getUsuario(db, username, password)
	if err != nil {
		mensagem := fmt.Sprintf("%s", err)
		respondError(w, http.StatusInternalServerError, mensagem)
		return
	}

	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		mensagem := fmt.Sprintf("%s: %s", "Erro ID inválido", err)
		logger.Erro.Println(mensagem)

		respondError(w, http.StatusBadRequest, mensagem)
		return
	}

	if id > 0 {
		var usuarioModel = db.Collection("usuario")

		usuario, err := models.UmUsuario(usuarioModel, id)
		if err != nil {
			mensagem := fmt.Sprintf("%s: %s", "Erro ao recuperar usuário", err)
			respondError(w, http.StatusInternalServerError, mensagem)
			return
		}
		mensagem := fmt.Sprintf("Usuário [%v] recuperado no banco de dados", id)
		logger.Info.Println(mensagem)

		respondJSON(w, http.StatusOK, usuario)
	} else {
		mensagem := fmt.Sprint("ID do usuário menor ou igual a zero!")
		logger.Erro.Println(mensagem)

		respondError(w, http.StatusLengthRequired, mensagem)
		return
	}
}

//Recuperar usuário
func getUsuario(db db.Database, login, senha string) (models.Usuario, error) {
	var usuario models.Usuario

	if login != "" && senha != "" {
		usuario.Login = login
		usuario.Senha = senha

		var usuarioModel = db.Collection("usuario")
		var interf models.Metodos

		interf = usuario

		var usuarioRecuperado models.Usuario
		usuarioRecuperado, err := interf.Logar(usuarioModel)
		if err != nil {
			return usuario, err
		}

		usuario = usuarioRecuperado

	}
	return usuario, nil
}
