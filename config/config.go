package config

import (
	"os"
	"strconv"
)

var porta, _ = strconv.Atoi(os.Getenv("MYSQL_PORT"))

//Config estrutura
type Config struct {
	DB *DBConfig
}

//DBConfig estrutura de banco de dados
type DBConfig struct {
	Dialect  string
	Host     string
	Port     int
	Username string
	Password string
	Name     string
	Charset  string
}

//GetConfig configurar dados do banco
func GetConfig() *Config {
	return &Config{
		DB: &DBConfig{
			Dialect:  "mysql",
			Host:     os.Getenv("MYSQL_HOSTNAME"),
			Port:     porta,
			Username: os.Getenv("MYSQL_USER"),
			Password: os.Getenv("MYSQL_PASSWORD"),
			Name:     os.Getenv("MYSQL_DATABASE"),
			Charset:  "utf8",
		},
	}
}
