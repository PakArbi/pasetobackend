package pasetobackend

import (
	"context"
	"fmt"
	"os"

	"github.com/aiteung/atdb"
	"github.com/whatsauth/watoken"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// mongodb
func MongoConnect(MongoString, dbname string) *mongo.Database {
	client, err := mongo.Connect(context.TODO(), options.Client().ApplyURI(os.Getenv(MongoString)))
	if err != nil {
		fmt.Printf("MongoConnect: %v\n", err)
	}
	return client.Database(dbname)
}

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


// < --- FUNCTION USER --->
func CreateUser(mongoconn *mongo.Database, collection string, userdata User) interface{} {
	hashedPassword, err := HashPassword(userdata.PasswordHash)
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
	useridstring := watoken.DecodeGetId(publicKey, tokenstring)
	if useridstring == "" {
		fmt.Println("expire token")
	}
	fmt.Println(useridstring)
	userdata.Private = privateKey
	userdata.Public = publicKey
	userdata.PasswordHash = hashedPassword

	return atdb.InsertOneDoc(mongoconn, collection, userdata)
}

func InsertUserdata(MongoConn *mongo.Database, usernameid, username, npm, password, passwordhash, email, role string) (InsertedID interface{}) {
	req := new(User)
	req.UsernameId = usernameid
	req.Username = username
	req.NPM = npm
	req.Password = password
	req.PasswordHash = passwordhash
	req.Email = email
	req.Role = role
	return InsertSatuDoc(MongoConn, "user", req)
}

func IsPasswordValid(mongoconn *mongo.Database, collection string, userdata User) bool {
	filter := bson.M{
		"$or": []bson.M{
			{"npm": userdata.NPM},
			{"email": userdata.Email},
		},
	}

	var res User
	err := mongoconn.Collection(collection).FindOne(context.TODO(), filter).Decode(&res)

	if err == nil {
		return CheckPasswordHash(userdata.PasswordHash, res.PasswordHash)
	}
	return false
}

func IsPasswordValidEmail(mongoconn *mongo.Database, collection string, userdata User) bool {
	filter := bson.M{
		"$or": []bson.M{
			{"email": userdata.Email},
			{"npm": userdata.NPM},
		},
	}

	var res User
	err := mongoconn.Collection(collection).FindOne(context.TODO(), filter).Decode(&res)

	if err == nil {
		return CheckPasswordHash(userdata.PasswordHash, res.PasswordHash)
	}
	return false
}

// < --- FUNCTION ADMIN --- >

func CreateAdmin(mongoconn *mongo.Database, collection string, admindata Admin) interface{} {
	hashedPassword, err := HashPassword(admindata.PasswordHash)
	if err != nil {
		return err
	}
	privateKey, publicKey := watoken.GenerateKey()
	adminid := admindata.Username
	tokenstring, err := watoken.Encode(adminid, privateKey)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(tokenstring)
	adminidstring := watoken.DecodeGetId(publicKey, tokenstring)
	if adminidstring == "" {
		fmt.Println("expire token")
	}
	fmt.Println(adminidstring)
	admindata.Private = privateKey
	admindata.Public = publicKey
	admindata.PasswordHash = hashedPassword

	return atdb.InsertOneDoc(mongoconn, collection, admindata)
}

func InsertAdmindata(MongoConn *mongo.Database, username, password, passwordhash, email, role string) (InsertedID interface{}) {
	req := new(Admin)
	req.Username = username
	req.Password = password
	req.PasswordHash = passwordhash
	req.Email = email
	req.Role = role
	return InsertSatuDoc(MongoConn, "admin", req)
}

func IsPasswordValidEmailAdmin(mongoconn *mongo.Database, collection string, admindata Admin) bool {
	filter := bson.M{
		"$or": []bson.M{
			{"email": admindata.Email},
		},
	}

	var res Admin
	err := mongoconn.Collection(collection).FindOne(context.TODO(), filter).Decode(&res)

	if err == nil {
		return CheckPasswordHash(admindata.PasswordHash, res.PasswordHash)
	}
	return false
}

// < --- FUNCTION CRUD --- >

func GetAllDocs(db *mongo.Database, col string, docs interface{}) interface{} {
	collection := db.Collection(col)
	filter := bson.M{}
	cursor, err := collection.Find(context.TODO(), filter)
	if err != nil {
		return fmt.Errorf("error GetAllDocs %s: %s", col, err)
	}
	err = cursor.All(context.TODO(), &docs)
	if err != nil {
		return err
	}
	return docs
}

func InsertOneDoc(db *mongo.Database, col string, doc interface{}) (insertedID primitive.ObjectID, err error) {
	result, err := db.Collection(col).InsertOne(context.Background(), doc)
	if err != nil {
		return insertedID, fmt.Errorf("kesalahan server : insert")
	}
	insertedID = result.InsertedID.(primitive.ObjectID)
	return insertedID, nil
}

func UpdateOneDoc(id primitive.ObjectID, db *mongo.Database, col string, doc interface{}) (err error) {
	filter := bson.M{"_id": id}
	result, err := db.Collection(col).UpdateOne(context.Background(), filter, bson.M{"$set": doc})
	if err != nil {
		return fmt.Errorf("error update: %v", err)
	}
	if result.ModifiedCount == 0 {
		err = fmt.Errorf("tidak ada data yang diubah")
		return
	}
	return nil
}

func DeleteOneDoc(_id primitive.ObjectID, db *mongo.Database, col string) error {
	collection := db.Collection(col)
	filter := bson.M{"_id": _id}
	result, err := collection.DeleteOne(context.TODO(), filter)
	if err != nil {
		return fmt.Errorf("error deleting data for ID %s: %s", _id, err.Error())
	}

	if result.DeletedCount == 0 {
		return fmt.Errorf("data with ID %s not found", _id)
	}

	return nil
}

// dipake
func InsertSatuDoc(db *mongo.Database, collection string, doc interface{}) (insertedID interface{}) {
	insertResult, err := db.Collection(collection).InsertOne(context.TODO(), doc)
	if err != nil {
		fmt.Printf("InsertOneDoc: %v\n", err)
	}
	return insertResult.InsertedID
}

func DeleteDataUser(MongoConn *mongo.Database, colname string, npm string) (*mongo.DeleteResult, error) {
	filter := bson.M{"npm": npm}
	del, err := MongoConn.Collection(colname).DeleteOne(context.TODO(), filter)
	if err != nil {
		return nil, err
	}
	return del, nil
}

func UpdateDataUser(MongoConn *mongo.Database, colname, npm, Username, Email, Role string) error {
	filter := bson.M{"npm": npm}
	update := bson.M{
		"$set": bson.M{
			"username": Username,
			"email":    Email,
			"role":     Role,
		},
	}

	_, err := MongoConn.Collection(colname).UpdateOne(context.TODO(), filter, update)
	if err != nil {
		return err
	}

	return nil
}

func UpdateUserData(mongoconn *mongo.Database, collection string, filter bson.M, usr User) interface{} {
	updatedFilter := bson.M{"usernameid": usr.UsernameId}
	return atdb.ReplaceOneDoc(mongoconn, collection, updatedFilter, usr)
}

// dipake
func GetAllUser(MongoConn *mongo.Database, colname string, username string) []User {
	data := atdb.GetAllDoc[[]User](MongoConn, colname)
	return data
}

func GetOneUser(MongoConn *mongo.Database, colname string, userdata User) User {
	filter := bson.M{"username": userdata.Username}
	data := atdb.GetOneDoc[User](MongoConn, colname, filter)
	return data
}

func GetOneUserNPM(mongoconn *mongo.Database, colname, UserId string) (usr User) {
	filter := bson.M{"usernameid": UserId}
	usr = atdb.GetOneDoc[User](mongoconn, colname, filter)
	return
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