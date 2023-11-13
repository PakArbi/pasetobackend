package pasetobackend

import (
	"fmt"
	"testing"

	"github.com/aiteung/atdb"
	"github.com/whatsauth/watoken"
	"go.mongodb.org/mongo-driver/bson"
)

func TestCreateNewUserRole(t *testing.T) {
	var userdata User
	userdata.Username = "faisal"
	userdata.Password = "sankuy"
	userdata.Role = "user"
	mconn := SetConnection("MONGOSTRING", "PakArbi")
	CreateNewUserRole(mconn, "user", userdata)
}

func TestCreateNewAdminRole(t *testing.T) {
	var userdata User
	userdata.Username = "admin"
	userdata.Password = "admin123"
	userdata.Role = "admin"
	mconn := SetConnection("MONGOSTRING", "PakArbi")
	CreateNewUserRole(mconn, "admin", userdata)
}

// func TestDeleteUser(t *testing.T) {
// 	mconn := SetConnection("MONGOSTRING", "pasabar13")
// 	var userdata User
// 	userdata.Username = "lolz"
// 	DeleteUser(mconn, "user", userdata)
// }

func CreateNewUserToken(t *testing.T) {
	var userdata User
	userdata.Username = "faisal"
	userdata.Password = "sankuy"
	userdata.Role = "user"

	// Create a MongoDB connection
	mconn := SetConnection("MONGOSTRING", "PakArbi")

	// Call the function to create a user and generate a token
	err := CreateUserAndAddToken("your_private_key_env", mconn, "user", userdata)

	if err != nil {
		t.Errorf("Error creating user and token: %v", err)
	}
}

func CreateNewAdminToken(t *testing.T) {
	var userdata User
	userdata.Username = "admin"
	userdata.Password = "admin123"
	userdata.Role = "admin"

	// Create a MongoDB connection
	mconn := SetConnection("MONGOSTRING", "PakArbi")

	// Call the function to create a user and generate a token
	err := CreateUserAndAddToken("your_private_key_env", mconn, "user", userdata)

	if err != nil {
		t.Errorf("Error creating user and token: %v", err)
	}
}

func TestGFCPostHandlerUser(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "PakArbi")
	var userdata User
	userdata.Username = "faisal"
	userdata.Password = "sankuy"
	userdata.Role = "user"
	CreateNewUserRole(mconn, "user", userdata)
}

func TestGeneratePasswordHash(t *testing.T) {
	password := "sankuy"
	hash, _ := HashPassword(password) // ignore error for the sake of simplicity

	fmt.Println("Password:", password)
	fmt.Println("Hash:    ", hash)
	match := CheckPasswordHash(password, hash)
	fmt.Println("Match:   ", match)
}

func TestGenerateAdminPasswordHash(t *testing.T) {
	password := "admin123"
	hash, _ := HashPassword(password) // ignore error for the sake of simplicity

	fmt.Println("Password:", password)
	fmt.Println("Hash:    ", hash)
	match := CheckPasswordHash(password, hash)
	fmt.Println("Match:   ", match)
}

func TestGeneratePrivateKeyPaseto(t *testing.T) {
	privateKey, publicKey := watoken.GenerateKey()
	fmt.Println(privateKey)
	fmt.Println(publicKey)
	hasil, err := watoken.Encode("sankuy", privateKey)
	fmt.Println(hasil, err)
}

func TestGenerateAdminPrivateKeyPaseto(t *testing.T) {
	privateKey, publicKey := watoken.GenerateKey()
	fmt.Println(privateKey)
	fmt.Println(publicKey)
	hasil, err := watoken.Encode("admin123", privateKey)
	fmt.Println(hasil, err)
}

func TestHashFunction(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "PakArbi")
	var userdata User
	userdata.Username = "faisal"
	userdata.Password = "sankuy"

	filter := bson.M{"username": userdata.Username}
	res := atdb.GetOneDoc[User](mconn, "user", filter)
	fmt.Println("Mongo User Result: ", res)
	hash, _ := HashPassword(userdata.Password)
	fmt.Println("Hash Password : ", hash)
	match := CheckPasswordHash(userdata.Password, res.Password)
	fmt.Println("Match:   ", match)

}

func TestHashAdminFunction(t *testing.T) {
    mconn := SetConnection("MONGOSTRING", "PakArbi")
    var admindata Admin
    admindata.Username = "admin"
    admindata.Email = "admin@gmail.com"
    admindata.Password = "admin123"

    filterUsername := bson.M{"username": admindata.Username}
    filterEmail := bson.M{"email": admindata.Email}

    resByUsername := atdb.GetOneDoc[User](mconn, "admin", filterUsername)
    resByEmail := atdb.GetOneDoc[User](mconn, "admin", filterEmail)

    fmt.Println("Mongo User Result (by username): ", resByUsername)
    fmt.Println("Mongo User Result (by email): ", resByEmail)

    hash, _ := HashPassword(admindata.Password)
    fmt.Println("Hash Password : ", hash)

    matchByUsername := CheckPasswordHash(admindata.Password, resByUsername.Password)
    matchByEmail := CheckPasswordHash(admindata.Password, resByEmail.Password)

    fmt.Println("Match (by username):   ", matchByUsername)
    fmt.Println("Match (by email):   ", matchByEmail)
}


func TestIsPasswordValid(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "PakArbi")
	var userdata User
	userdata.Username = "faisal"
	userdata.Password = "sankuy"

	anu := IsPasswordValid(mconn, "user", userdata)
	fmt.Println(anu)
}

func TestUserFix(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "PakArbi")
	var userdata User
	userdata.Username = "faisal"
	userdata.Password = "sankuy"
	userdata.Role = "user"
	CreateUser(mconn, "user", userdata)
}

func TestIsAdminPasswordValid(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "PakArbi")
	var admindata User
	admindata.Username = "admin"
	admindata.Password = "admin123"

	anu := IsPasswordValid(mconn, "user", admindata)
	fmt.Println(anu)
}

func TestAdminFix(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "PakArbi")
	var admindata User
	admindata.Username = "admin"
	admindata.Password = "admin123"
	admindata.Role = "admin"
	CreateUser(mconn, "user", admindata)
}

