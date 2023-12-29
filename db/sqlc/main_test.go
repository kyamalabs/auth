package db

import (
	"context"
	"log"
	"os"
	"testing"

	"github.com/kyamagames/auth/utils"

	"github.com/jackc/pgx/v5/pgxpool"
)

var testStore Store

func TestMain(m *testing.M) {
	config, err := utils.LoadConfig("../../")
	if err != nil {
		log.Fatal("cannot load config: ", err)
	}

	connPool, err := pgxpool.New(context.Background(), config.DBSource)
	if err != nil {
		log.Fatal("cannot connect to the db: ", err)
	}

	testStore = NewStore(connPool)

	os.Exit(m.Run())
}
