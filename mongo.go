package pasetobackend

import (
	"context"
	"fmt"
	"os"
	"errors"

	"github.com/aiteung/atdb"
	"github.com/whatsauth/watoken"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

func GetConnectionMongo(MongoString, dbname string) *mongo.Database {
	MongoInfo := atdb.DBInfo{
		DBString: os.Getenv(MongoString),
		DBName:   dbname,
	}
	conn := atdb.MongoConnect(MongoInfo)
	return conn
}

func SetConnection(MONGOCONNSTRINGENV, dbname string) *mongo.Database {
	var DBmongoinfo = atdb.DBInfo{
		DBString: os.Getenv(MONGOCONNSTRINGENV),
		DBName:   dbname,
	}
	return atdb.MongoConnect(DBmongoinfo)
}

func CreateUser(mongoconn *mongo.Database, collection string, userdata User) interface{} {
	// Hash the password before storing it
	hashedPassword, err := HashPassword(userdata.Password)
	if err != nil {
		return err
	}
	privateKey, publicKey := watoken.GenerateKey()
	userid := userdata.Username
	tokenstring, err := watoken.Encode(userid, privateKey)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(tokenstring)
	// decode token to get userid
	useridstring := watoken.DecodeGetId(publicKey, tokenstring)
	if useridstring == "" {
		fmt.Println("expire token")
	}
	fmt.Println(useridstring)
	userdata.Private = privateKey
	userdata.Public = publicKey
	userdata.Password = hashedPassword

	// Insert the user data into the database
	return atdb.InsertOneDoc(mongoconn, collection, userdata)
}

func CreateAdmin(mongoconn *mongo.Database, collection string, admindata Admin) interface{} {
	// Hash the password before storing it
	hashedPassword, err := HashPassword(admindata.Password)
	if err != nil {
		return err
	}
	privateKey, publicKey := watoken.GenerateKey()
	userid := admindata.Email
	tokenstring, err := watoken.Encode(userid, privateKey)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(tokenstring)
	// decode token to get userid
	useridstring := watoken.DecodeGetId(publicKey, tokenstring)
	if useridstring == "" {
		fmt.Println("expire token")
	}
	fmt.Println(useridstring)
	admindata.Private = privateKey
	admindata.Public = publicKey
	admindata.Password = hashedPassword

	// Insert the user data into the database
	return atdb.InsertOneDoc(mongoconn, collection, admindata)
}

func GetNameAndPassowrd(mongoconn *mongo.Database, collection string) []User {
	user := atdb.GetAllDoc[[]User](mongoconn, collection)
	return user
}

func GetByNameOrEmail(mongoconn *mongo.Database, collection, identifier string) (User, error) {
    var user User

    filter := bson.M{
        "$or": []bson.M{
            {"username": identifier},
            {"email": identifier},
        },
    }

    err := atdb.GetOneDoc(mongoconn, collection, filter)
    if err != nil {
        return User{}, err
    }

    return user, nil
}


func GetOneDoc(mongoconn *mongo.Database, collection string, filter bson.M, result interface{}) error {
	ctx := context.TODO()

	err := mongoconn.Collection(collection).FindOne(ctx, filter).Decode(result)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return errors.New("document not found")
		}
		return err
	}

	return nil
}


func CreateNewUserRole(mongoconn *mongo.Database, collection string, userdata User) interface{} {
	// Hash the password before storing it
	hashedPassword, err := HashPassword(userdata.Password)
	if err != nil {
		return err
	}
	userdata.Password = hashedPassword

	// Insert the user data into the database
	return atdb.InsertOneDoc(mongoconn, collection, userdata)
}

func CreateUserAndAddedToeken(PASETOPRIVATEKEYENV string, mongoconn *mongo.Database, collection string, userdata User) interface{} {
	// Hash the password before storing it
	hashedPassword, err := HashPassword(userdata.Password)
	if err != nil {
		return err
	}
	userdata.Password = hashedPassword

	// Insert the user data into the database
	atdb.InsertOneDoc(mongoconn, collection, userdata)

	// Create a token for the user
	tokenstring, err := watoken.Encode(userdata.Username, os.Getenv(PASETOPRIVATEKEYENV))
	if err != nil {
		return err
	}
	userdata.Token = tokenstring

	// Update the user data in the database
	return atdb.ReplaceOneDoc(mongoconn, collection, bson.M{"username": userdata.Username}, userdata)
}

func CreateAdminAndAddedToken(PASETOPRIVATEKEYENV string, mongoconn *mongo.Database, collection string, admindata Admin) interface{} {
	// Hash the password before storing it
	hashedPassword, err := HashPassword(admindata.Password)
	if err != nil {
		return err
	}
	admindata.Password = hashedPassword

	// Insert the user data into the database
	atdb.InsertOneDoc(mongoconn, collection, admindata)

	// Create a token for the user
	tokenstring, err := watoken.Encode(admindata.Email, os.Getenv(PASETOPRIVATEKEYENV))
	if err != nil {
		return err
	}
	admindata.Token = tokenstring

	// Update the user data in the database
	return atdb.ReplaceOneDoc(mongoconn, collection, bson.M{"email": admindata.Email}, admindata)
}

func DeleteUser(mongoconn *mongo.Database, collection string, userdata User) interface{} {
	filter := bson.M{"username": userdata.Username}
	return atdb.DeleteOneDoc(mongoconn, collection, filter)
}

func ReplaceOneDoc(mongoconn *mongo.Database, collection string, filter bson.M, userdata User) interface{} {
	return atdb.ReplaceOneDoc(mongoconn, collection, filter, userdata)
}

func FindUser(mongoconn *mongo.Database, collection string, userdata User) User {
	filter := bson.M{"username": userdata.Username}
	return atdb.GetOneDoc[User](mongoconn, collection, filter)
}

func IsPasswordValid(mongoconn *mongo.Database, collection string, userdata User) bool {
	filter := bson.M{"username": userdata.Username}
	res := atdb.GetOneDoc[User](mongoconn, collection, filter)
	return CheckPasswordHash(userdata.Password, res.Password)
}

func CreateUserAndAddToken(privateKeyEnv string, mongoconn *mongo.Database, collection string, userdata User) error {
	// Hash the password before storing it
	hashedPassword, err := HashPassword(userdata.Password)
	if err != nil {
		return err
	}
	userdata.Password = hashedPassword

	// Create a token for the user
	tokenstring, err := watoken.Encode(userdata.Username, os.Getenv(privateKeyEnv))
	if err != nil {
		return err
	}

	userdata.Token = tokenstring

	// Insert the user data into the MongoDB collection
	if err := atdb.InsertOneDoc(mongoconn, collection, userdata.Username); err != nil {
		return nil // Mengembalikan kesalahan yang dikembalikan oleh atdb.InsertOneDoc
	}

	// Return nil to indicate success
	return nil
}

func InsertUserdata(MongoConn *mongo.Database, username, email, role, password string) (InsertedID interface{}) {
	req := new(User)
	req.Username = username
	req.Email = email
	req.Password = password
	req.Role = role
	return InsertOneDoc(MongoConn, "user", req)
}

func InsertAdmindata(MongoConn *mongo.Database, username, email, role, password string) (InsertedID interface{}) {
	req := new(Admin)
	req.Username = username
	req.Email = email
	req.Password = password
	req.Role = role
	return InsertOneDoc(MongoConn, "user", req)
}

func InsertOneDoc(db *mongo.Database, collection string, doc interface{}) (insertedID interface{}) {
	insertResult, err := db.Collection(collection).InsertOne(context.TODO(), doc)
	if err != nil {
		fmt.Printf("InsertOneDoc: %v\n", err)
	}
	return insertResult.InsertedID
}

func InsertUser(db *mongo.Database, collection string, userdata User) string {
	hash, _ := HashPassword(userdata.Password)
	userdata.Password = hash
	atdb.InsertOneDoc(db, collection, userdata)
	return "Username/Email : " + userdata.Username + "/" + userdata.Email + "\nPassword : " + userdata.Password
}

func InsertAdmin(db *mongo.Database, collection string, userdata User) string {
	hash, _ := HashPassword(userdata.Password)
	userdata.Password = hash
	atdb.InsertOneDoc(db, collection, userdata)
	return "Email : " + userdata.Email +  "\nPassword : " + userdata.Password
}
