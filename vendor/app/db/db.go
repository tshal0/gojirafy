package db

import (
	"database/sql"
	_ "github.com/denisenkom/go-mssqldb"
	_ "github.com/lib/pq"
	"log"
	_ "net/url"
	"strconv"
	_ "strconv"
)

type Env struct {
	Context DBContext
}

type DB struct {
	*sql.DB
}

func InitDB(dataSourceName string) (*DB, error) {

	db, err := sql.Open("mssql", "sqlserver://sa:L0rdOfTheRings!@localhost/SQLExpress?database=Gojira&connection+timeout=30")

	if err != nil {
		return nil, err
	}
	if err = db.Ping(); err != nil {
		return nil, err
	}
	return &DB{db}, nil
}

type User struct {
	UserID      int64
	AccessToken string
}

type DBContext interface {
	Users() ([]*User, error)
	SetAccessToken(int, string) error
}

func (db *DB) SetAccessToken(userId int, accessToken string) error {
	log.Println(db)
	_, err := db.Exec("UPDATE dbo.Users SET AccessToken='" + accessToken + "' WHERE UserID=" + strconv.Itoa(userId))
	log.Println(err)
	return err
}

func (db *DB) Users() ([]*User, error) {
	log.Println("USERS FUNC")
	rows, err := db.Query("SELECT * FROM dbo.Users")
	if err != nil {
		log.Println(err.Error())
		return nil, err
	}
	log.Println("USERS B CLOSE")
	defer rows.Close()
	log.Println("USERS AFTER CLOSE")

	users := make([]*User, 0)
	log.Println("ROWS")
	for rows.Next() {
		var user User
		err = rows.Scan(&user.UserID, &user.AccessToken)
		if err != nil {
			log.Println(err.Error())
		}
		users = append(users, &user)
	}

	return users, nil
}
