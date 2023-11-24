package pasetobackend

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"context"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"

	"github.com/aiteung/atdb"
	"github.com/whatsauth/watoken"
	"go.mongodb.org/mongo-driver/bson"
)

func GCFFindUserByID(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var datauser User
	err := json.NewDecoder(r.Body).Decode(&datauser)
	if err != nil {
		return err.Error()
	}
	user := FindUser(mconn, collectionname, datauser)
	return GCFReturnStruct(user)
}

func GCFFindAdminByEmail(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var dataadmin Admin
	err := json.NewDecoder(r.Body).Decode(&dataadmin)
	if err != nil {
		return err.Error()
	}

	// Jika email kosong, maka respon "false" dan data tidak ada
	if dataadmin.Email == "" {
		return "false"
	}

	// Jika ada email, mencari data admin
	admin := FindAdminByEmail(mconn, collectionname, dataadmin.Email)

	// Jika data admin ditemukan, mengembalikan data admin dalam format yang sesuai
	if admin != (Admin{}) {
		return GCFReturnStructAdmin(admin)
	}

	// Jika tidak ada data admin yang ditemukan, mengembalikan "false" dan data tidak ada
	return "false"
} 

func GCFFindUserByEmail(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var datauser User
	err := json.NewDecoder(r.Body).Decode(&datauser)
	if err != nil {
		return err.Error()
	}

	// Jika email kosong, maka respon "false" dan data tidak ada
	if datauser.Email == "" {
		return "false"
	}

	// Jika ada email, mencari data admin
	user := FindUserByEmail(mconn, collectionname, datauser.Email)

	// Jika data admin ditemukan, mengembalikan data admin dalam format yang sesuai
	if user != (User{}) {
		return GCFReturnStruct(user)
	}

	// Jika tidak ada data admin yang ditemukan, mengembalikan "false" dan data tidak ada
	return "false"
}

func GCFFindUserByName(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var datauser User
	err := json.NewDecoder(r.Body).Decode(&datauser)
	if err != nil {
		return err.Error()
	}

	// Jika email kosong, maka respon "false" dan data tidak ada
	if datauser.Username == "" {
		return "false"
	}

	// Jika ada email, mencari data pengguna
	user := FindUser(mconn, collectionname, datauser)

	// Jika data pengguna ditemukan, mengembalikan data pengguna dalam format yang sesuai
	if user != (User{}) {
		return GCFReturnStruct(user)
	}

	// Jika tidak ada data pengguna yang ditemukan, mengembalikan "false" dan data tidak ada
	return "false"
}

func GCFDeleteHandler(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var datauser User
	err := json.NewDecoder(r.Body).Decode(&datauser)
	if err != nil {
		return err.Error()
	}
	DeleteUser(mconn, collectionname, datauser)
	return GCFReturnStruct(datauser)
}

func GCFUpdateHandler(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var datauser User
	err := json.NewDecoder(r.Body).Decode(&datauser)
	if err != nil {
		return err.Error()
	}
	ReplaceOneDoc(mconn, collectionname, bson.M{"email": datauser.Email}, datauser)
	return GCFReturnStruct(datauser)
}

func GCFCreateHandler(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var datauser User
	err := json.NewDecoder(r.Body).Decode(&datauser)
	if err != nil {
		return err.Error()
	}

	// Hash the password before storing it
	hashedPassword, hashErr := HashPassword(datauser.Password)
	if hashErr != nil {
		return hashErr.Error()
	}
	datauser.Password = hashedPassword

	createErr := CreateNewUserRole(mconn, collectionname, datauser)
	fmt.Println(createErr)

	return GCFReturnStruct(datauser)
}

//Admin Handler
func GCFDeleteHandlerAdmin(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var dataadmin User
	err := json.NewDecoder(r.Body).Decode(&dataadmin)
	if err != nil {
		return err.Error()
	}
	DeleteUser(mconn, collectionname, dataadmin)
	return GCFReturnStruct(dataadmin)
}

func GCFUpdateHandlerAdmin(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var dataadmin User
	err := json.NewDecoder(r.Body).Decode(&dataadmin)
	if err != nil {
		return err.Error()
	}
	ReplaceOneDoc(mconn, collectionname, bson.M{"email": dataadmin.Email}, dataadmin)
	return GCFReturnStruct(dataadmin)
}

func GCFCreateHandlerAdmin(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var dataadmin Admin
	err := json.NewDecoder(r.Body).Decode(&dataadmin)
	if err != nil {
		return err.Error()
	}

	// Hash the password before storing it
	hashedPassword, hashErr := HashPassword(dataadmin.Password)
	if hashErr != nil {
		return hashErr.Error()
	}
	dataadmin.Password = hashedPassword

	createErr := CreateNewAdminRole(mconn, collectionname, dataadmin)
	fmt.Println(createErr)

	return GCFReturnStruct(dataadmin)
}
//end Admin Handler

func GCFRegisterUser(email, password, role, mongoConnectionString, dbName string) bool {
    // Menghubungkan ke database MongoDB
    client, err := mongo.Connect(context.TODO(), options.Client().ApplyURI(mongoConnectionString))
    if err != nil {
        // Gagal terhubung ke database
        return false
    }
    defer client.Disconnect(context.TODO())

    // Memilih koleksi (tabel) yang sesuai
    collection := client.Database(dbName).Collection("users")

    // Cek apakah pengguna dengan email tersebut sudah terdaftar
    existingUserFilter := bson.M{"email": email}
    existingUser := collection.FindOne(context.Background(), existingUserFilter)
    if existingUser.Err() == nil {
        // Pengguna dengan email tersebut sudah terdaftar
        return false
    }

    // Hash password menggunakan bcrypt sebelum menyimpannya ke database
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    if err != nil {
        // Gagal hash password
        return false
    }

    // Data pengguna baru
    newUser := User{
        Email: email,
        Password: string(hashedPassword),
        Role:     role,
    }

    // Menyimpan data pengguna ke database
    _, err = collection.InsertOne(context.Background(), newUser)
    if err != nil {
        // Gagal menyimpan data pengguna ke database
        return false
    }

    // Registrasi pengguna berhasil
    return true
}

func GCFRegisterAdmin(email, password, role, mongoConnectionString, dbName string) bool {
    // Menghubungkan ke database MongoDB
    client, err := mongo.Connect(context.TODO(), options.Client().ApplyURI(mongoConnectionString))
    if err != nil {
        // Gagal terhubung ke database
        return false
    }
    defer client.Disconnect(context.TODO())

    // Memilih koleksi (tabel) yang sesuai
    collection := client.Database(dbName).Collection("admin")

    // Cek apakah pengguna dengan email tersebut sudah terdaftar
    existingAdminFilter := bson.M{"email": email}
    existingAdmin := collection.FindOne(context.Background(), existingAdminFilter)
    if existingAdmin.Err() == nil {
        // Pengguna dengan email tersebut sudah terdaftar
        return false
    }

    // Hash password menggunakan bcrypt sebelum menyimpannya ke database
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    if err != nil {
        // Gagal hash password
        return false
    }

    // Data pengguna baru
    newAdmin := Admin{
        Email: email,
        Password: string(hashedPassword),
        Role:     role,
    }

    // Menyimpan data pengguna ke database
    _, err = collection.InsertOne(context.Background(), newAdmin)
    if err != nil {
        // Gagal menyimpan data pengguna ke database
        return false
    }

    // Registrasi pengguna berhasil
    return true
}
// Sesuaikan dengan kebutuhan dan struktur data yang Anda miliki. Pastikan atribut Role telah ditambahkan di struktur


func GFCPostHandlerUser(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	var Response Credential
	Response.Status = false

	// Mendapatkan data yang diterima dari permintaan HTTP POST
	var datauser User
	err := json.NewDecoder(r.Body).Decode(&datauser)
	if err != nil {
		Response.Message = "error parsing application/json: " + err.Error()
	} else {
		// Menggunakan variabel MONGOCONNSTRINGENV untuk string koneksi MongoDB
		mongoConnStringEnv := MONGOCONNSTRINGENV

		mconn := SetConnection(mongoConnStringEnv, dbname)

		// Lakukan pemeriksaan kata sandi menggunakan bcrypt
		if IsPasswordValid(mconn, collectionname, datauser) {
			Response.Status = true
			Response.Message = "Selamat Datang"
		} else {
			Response.Message = "Password Salah"
		}
	}

	// Mengirimkan respons sebagai JSON
	responseJSON, _ := json.Marshal(Response)
	return string(responseJSON)
}

//AdminPost
func GFCPostHandlerAdmin(MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	var Response Credential
	Response.Status = false

	// Mendapatkan data yang diterima dari permintaan HTTP POST
	var dataadmin Admin
	err := json.NewDecoder(r.Body).Decode(&dataadmin)
	if err != nil {
		Response.Message = "error parsing application/json: " + err.Error()
	} else {
		// Menggunakan variabel MONGOCONNSTRINGENV untuk string koneksi MongoDB
		mongoConnStringEnv := MONGOCONNSTRINGENV

		mconn := SetConnection(mongoConnStringEnv, dbname)

		// Lakukan pemeriksaan kata sandi menggunakan bcrypt
		if IsPasswordValidAdmin(mconn, collectionname, dataadmin) {
			Response.Status = true
			Response.Message = "Selamat Datang"
		} else {
			Response.Message = "Password Salah"
		}
	}

	// Mengirimkan respons sebagai JSON
	responseJSON, _ := json.Marshal(Response)
	return string(responseJSON)
}

func GCFPostHandler(PASETOPRIVATEKEYENV, MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	var Response Credential
	Response.Status = false
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var datauser User
	err := json.NewDecoder(r.Body).Decode(&datauser)
	if err != nil {
		Response.Message = "error parsing application/json: " + err.Error()
	} else {
		if IsPasswordValid(mconn, collectionname, datauser) {
			Response.Status = true
			tokenstring, err := watoken.Encode(datauser.Username, os.Getenv(PASETOPRIVATEKEYENV))
			if err != nil {
				Response.Message = "Gagal Encode Token : " + err.Error()
			} else {
				Response.Message = "Selamat Datang"
				Response.Token = tokenstring
			}
		} else {
			Response.Message = "Password Salah"
		}
	}

	return GCFReturnStruct(Response)
}

func GCFReturnStruct(DataStuct any) string {
	jsondata, _ := json.Marshal(DataStuct)
	return string(jsondata)
}

func GCFReturnStructAdmin(DataStuct any) string {
	jsondata, _ := json.Marshal(DataStuct)
	return string(jsondata)
}

func GCFLoginTest(email, password, MONGOCONNSTRINGENV, dbname, collectionname string) bool {
	// Membuat koneksi ke MongoDB
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)

	// Mencari data pengguna berdasarkan email
	filter := bson.M{"email": email}
	collection := collectionname
	res := atdb.GetOneDoc[User](mconn, collection, filter)

	// Memeriksa apakah pengguna ditemukan dalam database
	if res == (User{}) {
		return false
	}

	// Memeriksa apakah kata sandi cocok
	return CheckPasswordHash(password, res.Password)
}

func Login(Privatekey, MongoEnv, dbname, Colname string, r *http.Request) string {
	var resp Credential
	mconn := SetConnection(MongoEnv, dbname)
	var datauser User
	err := json.NewDecoder(r.Body).Decode(&datauser)
	if err != nil {
		resp.Message = "error parsing application/json: " + err.Error()
	} else {
		if IsPasswordValid(mconn, Colname, datauser) {
			tokenstring, err := watoken.Encode(datauser.Username, os.Getenv(Privatekey))
			if err != nil {
				resp.Message = "Gagal Encode Token : " + err.Error()
			} else {
				resp.Status = true
				resp.Message = "Selamat Datang"
				resp.Token = tokenstring
			}
		} else {
			resp.Message = "Password Salah"
		}
	}
	return GCFReturnStruct(resp)
}

func ReturnStringStruct(Data any) string {
	jsonee, _ := json.Marshal(Data)
	return string(jsonee)
}

func ReturnStringStructAdmin(Data any) string {
	jsonee, _ := json.Marshal(Data)
	return string(jsonee)
}

func RegisterUser(Mongoenv, dbname string, r *http.Request) string {
	resp := new(Credential)
	userdata := new(User)
	resp.Status = false
	conn := GetConnectionMongo(Mongoenv, dbname)
	err := json.NewDecoder(r.Body).Decode(&userdata)
	if err != nil {
		resp.Message = "error parsing application/json: " + err.Error()
	} else {
		resp.Status = true
		hash, err := HashPassword(userdata.Password)
		if err != nil {
			resp.Message = "Gagal Hash Password" + err.Error()
		}
		InsertUserdata(conn, userdata.Email, userdata.Role, hash)
		resp.Message = "Berhasil Input data"
	}
	response := ReturnStringStruct(resp)
	return response
}

func RegisterAdmin(Mongoenv, dbname string, r *http.Request) string {
	resp := new(Credential)
	admindata := new(Admin)
	resp.Status = false
	conn := GetConnectionMongo(Mongoenv, dbname)
	err := json.NewDecoder(r.Body).Decode(&admindata)
	if err != nil {
		resp.Message = "error parsing application/json: " + err.Error()
	} else {
		resp.Status = true
		hash, err := HashPassword(admindata.Password)
		if err != nil {
			resp.Message = "Gagal Hash Password" + err.Error()
		}
		InsertAdmindata(conn, admindata.Email, admindata.Role, hash)
		resp.Message = "Berhasil Input data"
	}
	response := ReturnStringStruct(resp)
	return response
}