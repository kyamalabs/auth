package main

import (
	"log"

	_ "github.com/jackc/pgx/v5"
	"github.com/kyamagames/auth/utils"
)

func main() {
	_, err := utils.LoadConfig(".")
	if err != nil {
		log.Fatal("cannot load config: ", err)
	}
}
