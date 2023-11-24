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
	userdata.Email = "faisalsidiq14@gmail.com"
	userdata.Password = "sankuy"
	userdata.Role = "user"
	mconn := SetConnection("MONGOSTRING", "PakArbi")
	CreateNewUserRole(mconn, "user", userdata)
}

func TestCreateNewAdminRole(t *testing.T) {
	var admindata Admin
	admindata.Email = "1214041@std.ulbi.ac.id"
	admindata.Password = "sankuy"
	admindata.Role = "admin"
	mconn := SetConnection("MONGOSTRING", "PakArbi")
	CreateNewAdminRole(mconn, "admin", admindata)
}

// func TestCreateNewAdminRole(t *testing.T) {
// 	var admindata Admin
// 	admindata.Email = "faisalsidiq14@gmail.com"
// 	admindata.Password = "sankuy"
// 	admindata.Role = "admin"
// 	mconn := SetConnection("MONGOSTRING", "PakArbi")

// 	// // Validate email format
// 	// if !CheckEmailFormat(admindata.Email) {
// 	// 	t.Error("Invalid email format")
// 	// }

// 	// Testing CreateNewAdminRole function
// 	result := CreateNewAdminRole(mconn, "admin", admindata)

// 	// Verify the functionality of CreateNewAdminRole
// 	success, ok := result.(bool)
// 	if !ok || !success {
// 		t.Error("Failed to create a new admin role")
// 	}

// 	// Optionally, add assertions or checks here to validate the created user role in the database.
// }

func CreateNewUserToken(t *testing.T) {
	var userdata User
	userdata.Email = "faisalsidiq14@gmail.com"
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
	var admindata Admin
	admindata.Email = "12114041@std.ulbi.ac.id"
	admindata.Password = "admin123"
	admindata.Role = "admin"

	// Create a MongoDB connection
	mconn := SetConnection("MONGOSTRING", "PakArbi")

	// Call the function to create a user and generate a token
	err := CreateAdminAndAddToken("your_private_key_env", mconn, "admin", admindata)

	if err != nil {
		t.Errorf("Error creating user and token: %v", err)
	}
}

func TestGFCPostHandlerUser(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "PakArbi")
	var userdata User
	userdata.Email = "faisalsidiq14@gmail.com"
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

// func TestGenerateAdminEmailHash(t *testing.T) {
// 	email := "faisalsidiq14@gmail.com"
// 	hash := HashEmail(email) // ignore error for the sake of simplicity

// 	fmt.Println("Email:", email)
// 	fmt.Println("Hash:    ", hash)
// 	match := CheckEmailHash(email, hash)
// 	fmt.Println("Match:   ", match)
// }

func TestGenerateAdminPasswordHash(t *testing.T) {
	password := "admin123"
	hash, _ := HashPassword(password) // ignore error for the sake of simplicity

	fmt.Println("Password:", password)
	fmt.Println("Hash:    ", hash)
	match := CheckPasswordHash(password, hash)
	fmt.Println("Match:   ", match)
}

// func TestGenerateAdminEmailHash(t *testing.T) {
// 	email := "1214041@std.ulbi.ac.id"
// 	hash := HashEmail(email) // ignore error for the sake of simplicity

// 	fmt.Println("Email:", email)
// 	fmt.Println("Hash:    ", hash)
// 	match := CheckEmailHash(email, hash)
// 	fmt.Println("Match:   ", match)
// }

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
	userdata.Email = "faisal"
	userdata.Password = "sankuy"

	filter := bson.M{"email": userdata.Email}
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
    admindata.Email = "admin@gmail.com"
    admindata.Password = "admin123"

    filterEmail := bson.M{"email": admindata.Email}

    resByEmail := atdb.GetOneDoc[User](mconn, "admin", filterEmail)

    fmt.Println("Mongo User Result (by email): ", resByEmail)

    hash, _ := HashPassword(admindata.Password)
    fmt.Println("Hash Password : ", hash)

    matchByEmail := CheckPasswordHash(admindata.Password, resByEmail.Password)

    fmt.Println("Match (by email):   ", matchByEmail)
}


func TestIsPasswordValid(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "PakArbi")
	var userdata User
	userdata.Email = "faisalsidiq14@gmail.com"
	userdata.Password = "sankuy"

	anu := IsPasswordValid(mconn, "user", userdata)
	fmt.Println(anu)
}

func TestUserFix(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "PakArbi")
	var userdata User
	userdata.Email = "faisalsidiq14@gmail.com"
	userdata.Password = "sankuy"
	userdata.Role = "user"
	CreateUser(mconn, "user", userdata)
}

func TestIsAdminPasswordValid(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "PakArbi")
	var admindata Admin
	admindata.Email = "1214041@std.ulbi.ac.id"
	admindata.Password = "admin123"

	anu := IsPasswordValidAdmin(mconn, "admin", admindata)
	fmt.Println(anu)
}

func TestAdminFix(t *testing.T) {
	mconn := SetConnection("MONGOSTRING", "PakArbi")
	var admindata Admin
	admindata.Email = "1214041@std.ulbi.ac.id"
	admindata.Password = "admin123"
	admindata.Role = "admin"
	CreateAdmin(mconn, "admin", admindata)
}

