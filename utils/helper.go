package utils

import (
	"fmt"
	"log"
	"unsafe"
)

// CheckErrFatal checar o erro
func CheckErrFatal(err error, msg string) {
	if err != nil {
		log.Printf("CheckErr(): %q\n", err)
		log.Fatalf("%s: %s", msg, err)
	}
}

// CheckErr checar o erro
func CheckErr(err error, msg string) string {
	mensagem := ""

	if err != nil {
		mensagem = fmt.Sprintf("CheckErr(): %s: %s", msg, err)
		log.Printf(mensagem)
	}

	return mensagem
}

//BytesToString converter bytes para string
func BytesToString(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))
}

//InBetween Intervalo de números
func InBetween(i, min, max int) bool {
	if (i >= min) && (i <= max) {
		return true
	} else {
		return false
	}
}

//IsEmpty verifica se esta vazio
func IsEmpty(data string) bool {
	if len(data) == 0 {
		return true
	} else {
		return false
	}
}
