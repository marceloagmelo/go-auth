package models

import (
	"errors"
	"fmt"
	"time"

	"github.com/marceloagmelo/go-auth/logger"
	"upper.io/db.v3"
)

//Usuario estrutura de usuário
type Usuario struct {
	ID              int       `db:"id" json:"id"`
	Nome            string    `db:"nome" json:"nome"`
	Senha           string    `db:"senha" json:"senha"`
	Email           string    `db:"email" json:"email"`
	DataCriacao     time.Time `db:"dtcriacao" json:"dtcriacao"`
	DataAtualizacao time.Time `db:"dtatualizacao" json:"dtatualizacao"`
	Status          int       `db:"status" json:"status"`
}

// Metodos interface
type Metodos interface {
	Adicionar(usuarioModel db.Collection) (string, error)
	Atualizar(usuarioModel db.Collection) error
	Logar(usuarioModel db.Collection) (Usuario, error)
}

//Adicionar usuário no banco de dados
func (usu Usuario) Adicionar(usuarioModel db.Collection) (string, error) {

	novoID, err := usuarioModel.Insert(usu)
	if err != nil {
		mensagem := fmt.Sprintf("%s: %s", "Gravando a usuário no banco de dados", err)
		logger.Erro.Println(mensagem)
		return "", err
	}
	strID := fmt.Sprintf("%v", novoID)
	mensagem := fmt.Sprintf("Usuário [%s] adicionado no banco de dados", strID)
	logger.Info.Println(mensagem)

	return strID, nil
}

//Atualizar um usuário no banco de dados
func (usu Usuario) Atualizar(usuarioModel db.Collection) error {
	resultado := usuarioModel.Find("id", usu.ID)
	if count, err := resultado.Count(); count < 1 {
		mensagem := ""
		if err != nil {
			mensagem = fmt.Sprintf("%s: %s", "Recuperando usuário no banco de dados", err)
		} else {
			mensagem = fmt.Sprintf("Usuário [%v] não encontrada!", usu.ID)
		}

		logger.Erro.Println(mensagem)

		return err
	}

	if err := resultado.Update(&usu); err != nil {
		mensagem := fmt.Sprintf("%s: %s", "Gravando o usuário no banco de dados", err)
		logger.Erro.Println(mensagem)
		return err
	}

	strID := fmt.Sprintf("%v", usu.ID)
	mensagem := fmt.Sprintf("Usuário [%s] atualizado no banco de dados", strID)
	logger.Info.Println(mensagem)

	return nil
}

//Apagar um usuário no banco de dados
func Apagar(usuarioModel db.Collection, id int) error {

	resultado := usuarioModel.Find("id=?", id)
	if count, err := resultado.Count(); count < 1 {
		mensagem := ""
		if err != nil {
			mensagem = fmt.Sprintf("%s: %s", "Erro ao recuperar usuário", err)
		}
		if count > 0 {
		} else {
			mensagem = fmt.Sprintf("Usuário [%v] não encontrado!", id)
			err = errors.New(mensagem)
		}

		if mensagem != "" {
			logger.Erro.Println(mensagem)
			return err
		}
	}
	if err := resultado.Delete(); err != nil {
		mensagem := fmt.Sprintf("%s: %s", "Erro ao apagar mensagem", err)
		logger.Erro.Println(mensagem)
		return err
	}

	return nil
}

//TodosUsuarios listar todos os usuários
func TodosUsuarios(usuarioModel db.Collection) ([]Usuario, error) {

	var usuarios []Usuario

	if err := usuarioModel.Find().All(&usuarios); err != nil {
		mensagem := fmt.Sprintf("%s: %s", "Erro ao listar todos os usuários", err)
		logger.Erro.Println(mensagem)
		return usuarios, err
	}

	return usuarios, nil
}

//ListarStatus listar usuários por status
func ListarStatus(usuarioModel db.Collection, status int) ([]Usuario, error) {

	var usuarios []Usuario

	resultado := usuarioModel.Find("status", status)
	if count, err := resultado.Count(); count < 1 {
		mensagem := ""
		if err != nil {
			mensagem = fmt.Sprintf("%s: %s", "Erro ao listar status de usuários", err)
		} else {
			mensagem = fmt.Sprintf("Usuários com status [%v] não encontrados!", status)
			err = errors.New(mensagem)
		}

		if mensagem != "" {
			logger.Erro.Println(mensagem)
			return usuarios, err
		}
	}

	if err := resultado.All(&usuarios); err != nil {
		mensagem := fmt.Sprintf("%s: %s", "Erro ao listar status de usuários", err)
		logger.Erro.Println(mensagem)
	}

	return usuarios, nil
}

//Logar de usuário no banco de dados
func (usu Usuario) Logar(usuarioModel db.Collection) (Usuario, error) {

	var usuario Usuario

	resultado := usuarioModel.Find("nome=? and senha=?", usu.Nome, usu.Senha)
	if count, err := resultado.Count(); count < 1 {
		mensagem := ""
		if err != nil {
			mensagem = fmt.Sprintf("%s: %s", "Erro ao tentar logar usuário", err)
		} else {
			mensagem = fmt.Sprintf("Verifique se o usuário [%s] existe ou senha inválida!", usu.Nome)
			err = errors.New(mensagem)
		}

		if mensagem != "" {
			logger.Erro.Println(mensagem)
			return usuario, err
		}
	}

	if err := resultado.One(&usuario); err != nil {
		mensagem := ""
		if err != nil {
			mensagem = fmt.Sprintf("%s: %s", "Erro ao recupear usuário", err)
		} else {
			mensagem = fmt.Sprintf("Usuário [%s] não encontrado!", usu.Nome)
		}

		logger.Erro.Println(mensagem)
		return usuario, err
	}

	return usuario, nil
}

//UmUsuario recuperar um usuário no banco de dados
func UmUsuario(usuarioModel db.Collection, id int) (Usuario, error) {

	var usuario Usuario

	resultado := usuarioModel.Find("id=?", id)
	if count, err := resultado.Count(); count < 1 {
		mensagem := ""
		if err != nil {
			mensagem = fmt.Sprintf("%s: %s", "Erro ao recuperar usuário", err)
		} else {
			mensagem = fmt.Sprintf("Usuário [%v] não encontrado!", id)
			err = errors.New(mensagem)
		}

		if mensagem != "" {
			logger.Erro.Println(mensagem)
			return usuario, err
		}
	}
	if err := resultado.One(&usuario); err != nil {
		mensagem := ""
		if err != nil {
			mensagem = fmt.Sprintf("%s: %s", "Erro ao recuperar usuário", err)
		} else {
			mensagem = fmt.Sprintf("Usuário [%v] não encontrado!", id)
		}

		logger.Erro.Println(mensagem)
		return usuario, err
	}

	return usuario, nil
}
