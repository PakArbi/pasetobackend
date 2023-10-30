package pasetobackend

import (
	"context"
	"fmt"
	"github.com/aiteung/atdb"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"os"
)

func MongoCreateConnection(MongoString, dbname string) *mongo.Database {
	MongoInfo := atdb.DBInfo{
		DBString: os.Getenv(MongoString),
		DBName:   dbname,
	}
	conn := atdb.MongoConnect(MongoInfo)
	return conn
}

func InsertOneDoc(db *mongo.Database, collection string, doc interface{}) (insertedID interface{}) {
	insertResult, err := db.Collection(collection).InsertOne(context.TODO(), doc)
	if err != nil {
		fmt.Printf("InsertOneDoc: %v\n", err)
	}
	return insertResult.InsertedID
}

func GetAllUser(MongoConn *mongo.Database, colname string) []User {
	data := atdb.GetAllDoc[[]User](MongoConn, colname)
	return data
}

func GetOneUser(MongoConn *mongo.Database, colname string, userdata User) User {
	filter := bson.M{"username": userdata.Username}
	data := atdb.GetOneDoc[User](MongoConn, colname, filter)
	return data
}

func PasswordValidator(MongoConn *mongo.Database, colname string, userdata User) bool {
	filter := bson.M{"username": userdata.Username}
	data := atdb.GetOneDoc[User](MongoConn, colname, filter)
	hashChecker := CompareHashPass(userdata.Password, data.Password)
	return hashChecker
}

func InsertUserdata(MongoConn *mongo.Database, username, role, password string) (InsertedID interface{}) {
	req := new(User)
	req.Username = username
	req.Password = password
	req.Role = role
	return InsertOneDoc(MongoConn, "user", req)
}

func CompareUsername(MongoConn *mongo.Database, Colname, username string) bool {
	filter := bson.M{"username": username}
	err := atdb.GetOneDoc[User](MongoConn, Colname, filter)
	users := err.Username
	if users == "" {
		return false
	}
	return true
}
