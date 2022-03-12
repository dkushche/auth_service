package account

import (
	"database/sql"
	"errors"
	"fmt"
	"io/ioutil"
	"regexp"

	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB

type Account struct {
	id      int
	uname   string
	upasswd string
	ulevel  uint
}

func InitDatabase(db_path string) error {
	var err error

	db, err = sql.Open("sqlite3", db_path)
	if err != nil {
		return fmt.Errorf("unable to open database %w", err)
	}

	if _, err = ioutil.ReadFile(db_path); err != nil {
		stmt, err := db.Prepare(`
			CREATE TABLE IF NOT EXISTS "accounts" (
				"ID" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
				"uname" TEXT NOT NULL UNIQUE,
				"upasswd" TEXT NOT NULL,
				"ulevel" UNSIGNED INT
			);
		`)

		if err != nil {
			return fmt.Errorf("unable to prepare init statement %w", err)
		}

		stmt.Exec()
	}

	return nil
}

func Get(uname string, upasswd string) (*Account, error) {
	uaccount := &Account{}
	validator := regexp.MustCompile(`^[a-zA-Z0-9]{8,14}$`).MatchString

	if !(validator(uname) && validator(upasswd)) {
		return nil, errors.New("malicious input")
	}

	row, err := db.Query(
		"SELECT * FROM accounts WHERE uname=$1 AND upasswd=$2;",
		uname, upasswd,
	)
	if err != nil {
		return nil, fmt.Errorf("creation of select query failed: %w", err)
	}

	if !row.Next() {
		return nil, errors.New("no such account")
	}

	err = row.Scan(&uaccount.id, &uaccount.uname,
		&uaccount.upasswd, &uaccount.ulevel)
	if err != nil {
		return nil, fmt.Errorf("scan failed: %w", err)
	}

	return uaccount, nil
}
