package pasetobackend

import (
	"fmt"
	"testing"

	"github.com/aiteung/atdb"
	"github.com/whatsauth/watoken"
	"go.mongodb.org/mongo-driver/bson"
)

var privatekey = "privatekey"
var publickeyb = "publickey"
var encode = "encode"

/* -- TEST USER START -- */

// Test Password Hash
func TestGeneratePasswordHash(t *testing.T) {
	passwordhash := "pakarbipass"
	hash, _ := HashPassword(passwordhash) // ignore error for the sake of simplicity

	fmt.Println("Password:", passwordhash)
	fmt.Println("Hash:    ", hash)
	match := CheckPasswordHash(passwordhash, hash)
	fmt.Println("Match:   ", match)
}

// Generate Private & Public Key
func TestGeneratePrivateKeyPaseto(t *testing.T) {
	privateKey, publicKey := watoken.GenerateKey()
	fmt.Println(privateKey)
	fmt.Println(publicKey)
	hasil, err := watoken.Encode("pakarbipass", privateKey)
	fmt.Println(hasil, err)
}

func TestHashFunction(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "PakArbi")
	var userdata User
	userdata.UsernameId = "D4TI1214000"
	userdata.Username = "pakarbi"
	userdata.PasswordHash = "pakarbipass"

	filter := bson.M{"usernameid": userdata.UsernameId}
	res := atdb.GetOneDoc[User](mconn, "user", filter)
	fmt.Println("Mongo User Result: ", res)
	hash, _ := HashPassword(userdata.PasswordHash)
	fmt.Println("Hash Password : ", hash)
	match := CheckPasswordHash(userdata.PasswordHash, res.PasswordHash)
	fmt.Println("Match:   ", match)
}

func TestIsPasswordValid(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "PakArbi")
	var userdata User
	userdata.UsernameId = "D4TI1214000"
	userdata.Username = "pakarbi"
	userdata.PasswordHash = "pakarbipass"

	anu := IsPasswordValid(mconn, "user", userdata)
	fmt.Println(anu)
}

func TestUserFix(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "PakArbi")
	var userdata User
	userdata.UsernameId = "D4TI1214000"
	userdata.Username = "pakarbi"
	userdata.NPM = "1214000"
	userdata.Password = "pakarbipass"
	userdata.PasswordHash = "pakarbipass"
	userdata.Email = "1214000@std.ulbi.ac.id"
	userdata.Role = "user"
	CreateUser(mconn, "user", userdata)
}

func TestTokenEncoder(t *testing.T) {
	conn := GetConnectionMongo("MONGOSTRING", "PakArbi")
	privateKey, publicKey := watoken.GenerateKey()
	userdata := new(User)
	userdata.UsernameId = "D4TI1214000"
	userdata.Username = "pakarbi"
	userdata.Password = "pakarbipass"

	data := GetOneUser(conn, "user", User{
		UsernameId: userdata.UsernameId,
		Username:   userdata.Username,
		Password:   userdata.Password,
	})
	fmt.Println("Private Key : ", privateKey)
	fmt.Println("Public Key : ", publicKey)
	fmt.Printf("%+v", data)
	fmt.Println(" ")

	encode := TokenEncoder(data.UsernameId, privateKey)
	fmt.Printf("%+v", encode)
}

func TestCompareUsername(t *testing.T) {
	conn := GetConnectionMongo("MONGOSTRING", "PakArbi")
	deco := watoken.DecodeGetId("public",
		"token")
	compare := CompareUsername(conn, "user", deco)
	fmt.Println(compare)
}

/* -- TEST USER END -- */

/* ======================================================== */

/* -- TEST ADMIN START -- */

// Test Admin
func TestAdminFix(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "PakArbi")
	var admindata Admin
	admindata.Username = "adminpakarbi"
	admindata.Password = "adminpakarbipass"
	admindata.PasswordHash = "adminpakarbipass"
	admindata.Email = "PakArbi2023@std.ulbi.ac.id"
	admindata.Role = "admin"
	CreateAdmin(mconn, "admin", admindata)
}

func TestEncodeWithRole(t *testing.T) {
	privateKey, publicKey := watoken.GenerateKey()
	role := "admin"
	email := "PakArbi2023@std.ulbi.ac.id"
	encoder, err := EncodeWithRole(role, email, privateKey)

	fmt.Println(" error :", err)
	fmt.Println("Private :", privateKey)
	fmt.Println("Public :", publicKey)
	fmt.Println("encode: ", encoder)

}

func TestGeneratePrivateKeyPasetoAdmin(t *testing.T) {
	privateKey, publicKey := watoken.GenerateKey()
	fmt.Println(privateKey)
	fmt.Println(publicKey)
	hasil, err := watoken.Encode("adminpakarbipass", privateKey)
	fmt.Println(hasil, err)
}

/* -- TEST ADMIN END -- */

func TestDecodeToken(t *testing.T) {
	deco := watoken.DecodeGetId("public",
		"token")
	fmt.Println(deco)
}

func TestDecoder2(t *testing.T) {
	pay, err := Decoder(publickeyb, encode)
	user, _ := DecodeGetUser(publickeyb, encode)
	npm, _ := DecodeGetNPM(publickeyb, encode)
	role, _ := DecodeGetRole(publickeyb, encode)
	use, ro := DecodeGetRoleandUser(publickeyb, encode)
	fmt.Println("user :", user)
	fmt.Println("npm :", npm)
	fmt.Println("role :", role)
	fmt.Println("user and role :", use, ro)
	fmt.Println("err : ", err)
	fmt.Println("payload : ", pay)
}
