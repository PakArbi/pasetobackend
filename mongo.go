package pasetobackend

import (
	"context"
	"fmt"
	"os"
	"regexp"
	// "crypto/sha256"
    // "encoding/hex"
	

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
	userid := userdata.Email
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
	adminid := admindata.Email
	tokenstring, err := watoken.Encode(adminid, privateKey)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(tokenstring)
	// decode token to get userid
	adminidstring := watoken.DecodeGetId(publicKey, tokenstring)
	if adminidstring == "" {
		fmt.Println("expire token")
	}
	fmt.Println(adminidstring)
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

func GetEmailAndPassword(mongoconn *mongo.Database, collection string) []User {
    users := atdb.GetAllDoc[[]User](mongoconn, collection)
    validEmailUsers := make([]User, 0)

    for _, user := range users {
        if CheckEmailFormat(user.Email) {
            validEmailUsers = append(validEmailUsers, user)
        }
    }
    return validEmailUsers
}

func GetEmailAndPasswordAdmin(mongoconn *mongo.Database, collection string) []Admin {
    admins := atdb.GetAllDoc[[]Admin](mongoconn, collection)
    validEmailAdmin := make([]Admin, 0)

    for _, admin := range admins {
        if CheckEmailFormat(admin.Email) {
            validEmailAdmin = append(validEmailAdmin, admin)
        }
    }
    return validEmailAdmin
}


func CreateNewUserRole(mongoconn *mongo.Database, collection string, userdata User) interface{} {
	//Hash the Email before storing it
	// Hash the Email before storing it
    hashedEmail := HashEmail(userdata.Email)
	
	// Hash the password before storing it
	hashedPassword, err := HashPassword(userdata.Password)
	if err != nil {
		return err
	}

	userdata.Email = hashedEmail
	userdata.Password = hashedPassword

	// Insert the user data into the database
	return atdb.InsertOneDoc(mongoconn, collection, userdata)
}

func CreateNewAdminRole(mongoconn *mongo.Database, collection string, admindata Admin) interface{} {
	// Hash the password before storing it
	hashedPassword, err := HashPassword(admindata.Password)
	if err != nil {
		return err
	}
	admindata.Password = hashedPassword

	// Insert the user data into the database
	return atdb.InsertOneDoc(mongoconn, collection, admindata)
}

func CreateUserAndAddedToeken(PASETOPRIVATEKEYENV string, mongoconn *mongo.Database, collection string, userdata User) interface{} {
	// Hash the Email before storing it
    hashedEmail := HashEmail(userdata.Email)
	// Hash the password before storing it
	hashedPassword, err := HashPassword(userdata.Password)
	if err != nil {
		return err
	}
	userdata.Email = hashedEmail
	userdata.Password = hashedPassword

	// Insert the user data into the database
	atdb.InsertOneDoc(mongoconn, collection, userdata)

	// Create a token for the user
	tokenstring, err := watoken.Encode(userdata.Email, os.Getenv(PASETOPRIVATEKEYENV))
	if err != nil {
		return err
	}
	userdata.Token = tokenstring

	// Update the user data in the database
	return atdb.ReplaceOneDoc(mongoconn, collection, bson.M{"email": userdata.Email}, userdata)
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
	filter := bson.M{"email": userdata.Email}
	return atdb.DeleteOneDoc(mongoconn, collection, filter)
}

func ReplaceOneDoc(mongoconn *mongo.Database, collection string, filter bson.M, userdata User) interface{} {
	return atdb.ReplaceOneDoc(mongoconn, collection, filter, userdata)
}

func ReplaceOneDocAdmin(mongoconn *mongo.Database, collection string, filter bson.M, admindata Admin) interface{} {
	return atdb.ReplaceOneDoc(mongoconn, collection, filter, admindata)
}

func FindUser(mongoconn *mongo.Database, collection string, userdata User) User {
	filter := bson.M{"email": userdata.Email}
	return atdb.GetOneDoc[User](mongoconn, collection, filter)
}

func FindAdmin(mongoconn *mongo.Database, collection string, admindata Admin) Admin {
	filter := bson.M{"email": admindata.Email}
	return atdb.GetOneDoc[Admin](mongoconn, collection, filter)
}

func FindUserByEmail(mongoconn *mongo.Database, collection string, email string) User {
	filter := bson.M{"email": email}
	return atdb.GetOneDoc[User](mongoconn, collection, filter)
}

func FindAdminByEmail(mongoconn *mongo.Database, collection string, email string) Admin {
	filter := bson.M{"email": email}
	return atdb.GetOneDoc[Admin](mongoconn, collection, filter)
}

func IsPasswordValid(mongoconn *mongo.Database, collection string, userdata User) bool {
	filter := bson.M{"email": userdata.Email}
	res := atdb.GetOneDoc[User](mongoconn, collection, filter)
	return CheckPasswordHash(userdata.Password, res.Password)
}

func IsPasswordValidAdmin(mongoconn *mongo.Database, collection string, admindata Admin) bool {
	filter := bson.M{"email": admindata.Email}
	res := atdb.GetOneDoc[Admin](mongoconn, collection, filter)
	return CheckPasswordHash(admindata.Password, res.Password)
}

func CreateUserAndAddToken(privateKeyEnv string, mongoconn *mongo.Database, collection string, userdata User) error {
	// Hash the password before storing it
	hashedPassword, err := HashPassword(userdata.Password)
	if err != nil {
		return err
	}
	userdata.Password = hashedPassword

	// Create a token for the user
	tokenstring, err := watoken.Encode(userdata.Email, os.Getenv(privateKeyEnv))
	if err != nil {
		return err
	}

	userdata.Token = tokenstring

	// Insert the user data into the MongoDB collection
	if err := atdb.InsertOneDoc(mongoconn, collection, userdata.Email); err != nil {
		return nil // Mengembalikan kesalahan yang dikembalikan oleh atdb.InsertOneDoc
	}

	// Return nil to indicate success
	return nil
}

//Admin
func CreateAdminAndAddToken(privateKeyEnv string, mongoconn *mongo.Database, collection string, admindata Admin) error {
	// Hash the password before storing it
	hashedPassword, err := HashPassword(admindata.Password)
	if err != nil {
		return err
	}
	admindata.Password = hashedPassword

	// Create a token for the user
	tokenstring, err := watoken.Encode(admindata.Email, os.Getenv(privateKeyEnv))
	if err != nil {
		return err
	}

	admindata.Token = tokenstring

	// Insert the user data into the MongoDB collection
	if err := atdb.InsertOneDoc(mongoconn, collection, admindata.Email); err != nil {
		return nil // Mengembalikan kesalahan yang dikembalikan oleh atdb.InsertOneDoc
	}

	// Return nil to indicate success
	return nil
}

func InsertUserdata(MongoConn *mongo.Database, email, role, password string) (InsertedID interface{}) {
	req := new(User)
	// req.Username = username
	req.Email = email
	req.Password = password
	req.Role = role
	return InsertOneDoc(MongoConn, "user", req)
}

func InsertAdmindata(MongoConn *mongo.Database, email, role, password string) (InsertedID interface{}) {
	req := new(Admin)
	// req.Username = username
	req.Email = email
	req.Password = password
	req.Role = role
	return InsertOneDoc(MongoConn, "admin", req)
}

func InsertOneDoc(db *mongo.Database, collection string, doc interface{}) (insertedID interface{}) {
	insertResult, err := db.Collection(collection).InsertOne(context.TODO(), doc)
	if err != nil {
		fmt.Printf("InsertOneDoc: %v\n", err)
	}
	return insertResult.InsertedID
}

func InsertUser(db *mongo.Database, collection string, userdata User) string {
    hashedEmail := HashEmail(userdata.Email)
    hash, _ := HashPassword(userdata.Password)
    userdata.Email = hashedEmail
    userdata.Password = hash
    atdb.InsertOneDoc(db, collection, userdata)
    return "Email : " + hashedEmail + "\nPassword : " + userdata.Password
}

func InsertAdmin(db *mongo.Database, collection string, admindata Admin) string {
	hashedEmail := HashEmail(admindata.Email)
    hash, _ := HashPassword(admindata.Password)
    admindata.Email = hashedEmail
    admindata.Password = hash
	atdb.InsertOneDoc(db, collection, admindata)
	return "Email : " + admindata.Email +  "\nPassword : " + admindata.Password
}

//checkemail untuk kampus ulbi
func CheckEmailFormat(email string) bool {
	// Regular expression pattern for email validation including npm@std.ulbi.ac.id format
	emailRegexPattern := `^[a-zA-Z0-9._%+-]+@std\.ulbi\.ac\.id$`
	match, _ := regexp.MatchString(emailRegexPattern, email)
	return match
}