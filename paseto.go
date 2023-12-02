package pasetobackend

import (
	"encoding/json"
	"net/http"
	"os"
	"regexp"

	"github.com/whatsauth/watoken"
	// "go.mongodb.org/mongo-driver/bson"
)

// NewEmailValidator membuat instance baru dari EmailValidator
func NewEmailValidator() *EmailValidator {
	return &EmailValidator{
		regexPattern: `^[a-zA-Z0-9._%+-]+@std.ulbi.ac.id$`,
	}
}

// IsValid memeriksa apakah email sesuai dengan pola npm@std.ulbi.ac.id
func (v *EmailValidator) IsValid(email string) bool {
	match, _ := regexp.MatchString(v.regexPattern, email)
	return match
}

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

// Login User NPM
func GCFPostHandler(PASETOPRIVATEKEYENV, MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	var Response Credential
	Response.Status = false
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var datauser User
	err := json.NewDecoder(r.Body).Decode(&datauser)
	if err != nil {
		Response.Message = "error parsing application/json: " + err.Error()
	} else {
		// Assuming either email or npm is provided in the request
		if IsPasswordValid(mconn, collectionname, datauser) {
			Response.Status = true
			// Using NPM as identifier, you can modify this as needed
			tokenstring, err := watoken.Encode(datauser.NPM, os.Getenv(PASETOPRIVATEKEYENV))
			if err != nil {
				Response.Message = "Gagal Encode Token : " + err.Error()
			} else {
				Response.Message = "Selamat Datang"
				Response.Token = tokenstring
			}
		} else {
			Response.Message = "NPM atau Password Salah"
		}
	}

	return GCFReturnStruct(Response)
}

// Login User Email
func GCFPostHandlerEmail(PASETOPRIVATEKEYENV, MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	var Response Credential
	Response.Status = false
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var datauser User
	err := json.NewDecoder(r.Body).Decode(&datauser)
	if err != nil {
		Response.Message = "error parsing application/json: " + err.Error()
	} else {
		// Validasi email harus menggunakan npm@std.ulbi.ac.id sesuai dengan email kampus didaftarkan sebelum melakukan login
		validator := NewEmailValidator()
		if !validator.IsValid(datauser.Email) {
			Response.Message = "Email is not valid"
			response := GCFReturnStruct(Response)
			return response
		}

		// reguest npm or email
		if IsPasswordValidEmail(mconn, collectionname, datauser) {
			Response.Status = true
			// Menggunakan npm identifikasi, Anda bisa modifikasi sesuai keinginan
			tokenstring, err := watoken.Encode(datauser.Email, os.Getenv(PASETOPRIVATEKEYENV))
			if err != nil {
				Response.Message = "Gagal Encode Token : " + err.Error()
			} else {
				Response.Message = "Selamat Datang"
				Response.Token = tokenstring
			}
		} else {
			Response.Message = "Email atau Password Salah"
		}
	}

	return GCFReturnStruct(Response)
}

func GCFReturnStruct(DataStuct any) string {
	jsondata, _ := json.Marshal(DataStuct)
	return string(jsondata)
}

// Login Admin
func LoginAdmin(Privatekey, MongoEnv, dbname, Colname string, r *http.Request) string {
	var resp Credential
	mconn := SetConnection(MongoEnv, dbname)
	var dataadmin Admin
	err := json.NewDecoder(r.Body).Decode(&dataadmin)
	if err != nil {
		resp.Message = "error parsing application/json: " + err.Error()
	} else {
		if IsPasswordValidAdmin(mconn, Colname, dataadmin) {
			tokenstring, err := watoken.Encode(dataadmin.Username, os.Getenv(Privatekey))
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

//

// Register User
func Register(Mongoenv, dbname string, r *http.Request) string {
	resp := new(Credential)
	userdata := new(User)
	resp.Status = false
	conn := GetConnectionMongo(Mongoenv, dbname)
	err := json.NewDecoder(r.Body).Decode(&userdata)
	if err != nil {
		resp.Message = "error parsing application/json: " + err.Error()
	} else {
		resp.Status = true

		// Validasi email sebelum proses pendaftaran
		validator := NewEmailValidator()
		if !validator.IsValid(userdata.Email) {
			resp.Message = "Email is not valid"
			resp.Status = false
			response := ReturnStringStruct(resp)
			return response
		}

		hash, err := HashPassword(userdata.PasswordHash)
		if err != nil {
			resp.Message = "Gagal Hash Password" + err.Error()
		}
		InsertUserdata(conn, userdata.Username, userdata.NPM, userdata.Password, hash, userdata.Email, userdata.Role)
		resp.Message = "Berhasil Input data"
	}
	response := ReturnStringStruct(resp)
	return response
}

// Register Admin
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

		// Validasi email sebelum proses pendaftaran
		validator := NewEmailValidator()
		if !validator.IsValid(admindata.Email) {
			resp.Message = "Email is not valid"
			resp.Status = false
			response := ReturnStringStruct(resp)
			return response
		}

		hash, err := HashPassword(admindata.PasswordHash)
		if err != nil {
			resp.Message = "Gagal Hash Password" + err.Error()
		}
		InsertAdmindata(conn, admindata.Username, admindata.Password, hash, admindata.Email, admindata.Role)
		resp.Message = "Berhasil Input data"
	}
	response := ReturnStringStruct(resp)
	return response
}

// Get User
func GetDataUserFromGCF(PublicKey, MongoEnv, dbname, colname string, r *http.Request) string {
	req := new(Response)
	conn := GetConnectionMongo(MongoEnv, dbname)
	cihuy := new(ResponseGet)
	err := json.NewDecoder(r.Body).Decode(&cihuy)
	if err != nil {
		req.Status = false
		req.Message = "error parsing application/json: " + err.Error()
	} else {
		checktoken := watoken.DecodeGetId(os.Getenv(PublicKey), cihuy.Token)
		compared := CompareUsername(conn, colname, checktoken)
		if compared != true {
			req.Status = false
			req.Message = "Data Username tidak ada di database"
		} else {
			datauser := GetAllUser(conn, colname)
			req.Status = true
			req.Message = "data User berhasil diambil"
			req.Data = datauser
		}
	}
	return ReturnStringStruct(req)
}

// // Register Admin
// func RegisterAdmin(Mongoenv, dbname string, r *http.Request) string {
// 	resp := new(Credential)
// 	admindata := new(Admin)
// 	resp.Status = false
// 	conn := GetConnectionMongo(Mongoenv, dbname)
// 	err := json.NewDecoder(r.Body).Decode(&admindata)
// 	if err != nil {
// 		resp.Message = "error parsing application/json: " + err.Error()
// 	} else {
// 		resp.Status = true
// 		hash, err := HashPassword(admindata.PasswordHash)
// 		if err != nil {
// 			resp.Message = "Gagal Hash Password" + err.Error()
// 		}
// 		InsertAdmindata(conn, admindata.Username, admindata.Password, hash, admindata.Email, admindata.Role)
// 		resp.Message = "Berhasil Input data"
// 	}
// 	response := ReturnStringStruct(resp)
// 	return response
// }

func GetDataUserForAdmin(PublicKey, MongoEnv, dbname, colname string, r *http.Request) string {
	req := new(Response)
	conn := GetConnectionMongo(MongoEnv, dbname)
	tokenlogin := r.Header.Get("Login")
	if tokenlogin == "" {
		req.Status = false
		req.Message = "Header Login Not Found"
	} else {
		checktoken, err := DecodeGetUser(os.Getenv(PublicKey), tokenlogin)
		if err != nil {
			req.Status = false
			req.Message = "tidak ada data username : " + tokenlogin
		}
		compared := CompareUsername(conn, colname, checktoken)
		if compared != true {
			req.Status = false
			req.Message = "Data User tidak ada"
		} else {
			datauser := GetAllUser(conn, colname)
			req.Status = true
			req.Message = "data User berhasil diambil"
			req.Data = datauser
		}
	}
	return ReturnStringStruct(req)
}