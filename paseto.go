package pasetobackend

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strconv"

	"github.com/gofiber/fiber/v2"
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
func LoginUserNPM(PASETOPRIVATEKEYENV, MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
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
func LoginUserEmail(PASETOPRIVATEKEYENV, MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
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
func LoginAdmin(PASETOPRIVATEKEYENV, MONGOCONNSTRINGENV, dbname, collectionname string, r *http.Request) string {
	var Response Credential
	Response.Status = false
	mconn := SetConnection(MONGOCONNSTRINGENV, dbname)
	var dataadmin Admin
	err := json.NewDecoder(r.Body).Decode(&dataadmin)
	if err != nil {
		Response.Message = "error parsing application/json: " + err.Error()
	} else {
		// Validasi email harus menggunakan npm@std.ulbi.ac.id sesuai dengan email kampus didaftarkan sebelum melakukan login
		validator := NewEmailValidator()
		if !validator.IsValid(dataadmin.Email) {
			Response.Message = "Email is not valid"
			response := GCFReturnStruct(Response)
			return response
		}

		// reguest npm or email
		if IsPasswordValidEmailAdmin(mconn, collectionname, dataadmin) {
			Response.Status = true
			// Menggunakan npm identifikasi, Anda bisa modifikasi sesuai keinginan
			tokenstring, err := watoken.Encode(dataadmin.Email, os.Getenv(PASETOPRIVATEKEYENV))
			if err != nil {
				Response.Message = "Gagal Encode Token : " + err.Error()
			} else {
				Response.Message = "Selamat Datang Admin"
				Response.Token = tokenstring
			}
		} else {
			Response.Message = "Email atau Password Salah"
		}
	}

	return GCFReturnStruct(Response)
}

func ReturnStringStruct(Data any) string {
	jsonee, _ := json.Marshal(Data)
	return string(jsonee)
}

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
		InsertUserdata(conn, userdata.UsernameId, userdata.Username, userdata.NPM, userdata.Password, hash, userdata.Email, userdata.Role)
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

/* --CRUD USER-- */

// Get All User
func GetAllDataUser(PublicKey, MongoEnv, dbname, colname string, r *http.Request) string {
	req := new(Response)
	conn := GetConnectionMongo(MongoEnv, dbname)
	tokenlogin := r.Header.Get("Login")
	if tokenlogin == "" {
		req.Status = false
		req.Message = "Header Login Not Found"
	} else {
		// Dekode token untuk mendapatkan username
		username, err := DecodeGetUser(os.Getenv(PublicKey), tokenlogin)
		if err != nil {
			req.Status = false
			req.Message = "Tidak ada data username: " + tokenlogin
		} else {
			// Langsung ambil data user berdasarkan username
			datauser := GetAllUser(conn, colname, username)
			if datauser == nil {
				req.Status = false
				req.Message = "Data User tidak ada"
			} else {
				req.Status = true
				req.Message = "Data User berhasil diambil"
				req.Data = datauser
			}
		}
	}
	return ReturnStringStruct(req)
}

// Get One User
func GetOneDataUserNPM(PublicKey, MongoEnv, dbname, colname string, r *http.Request) string {
	req := new(Response)
	conn := GetConnectionMongo(MongoEnv, dbname)
	tokenlogin := r.Header.Get("Login")
	if tokenlogin == "" {
		req.Status = false
		req.Message = "Header Login Not Found"
	} else {
		npm, err := DecodeGetNPM(os.Getenv(PublicKey), tokenlogin)
		if err != nil {
			req.Status = false
			req.Message = "Error parsing application/json: " + err.Error()
		} else {
			datauser := GetOneUserNPM(conn, colname, npm)
			if datauser == (User{}) {
				req.Status = false
				req.Message = "Data User tidak ditemukan"
			} else {
				req.Status = true
				req.Message = "Data User berhasil diambil"
				req.Data = []User{datauser} // Ubah ke slice dari User
			}
		}
	}
	return ReturnStringStruct(req)
}

func GetOneEmployee(PublicKey, MongoEnv, dbname, colname string, r *http.Request) string {

	req := new(ResponseUser)
	resp := new(RequestUser)
	conn := GetConnectionMongo(MongoEnv, dbname)
	tokenlogin := r.Header.Get("Login")
	if tokenlogin == "" {
		req.Status = false
		req.Message = "Header Login Not Found"
	} else {
		err := json.NewDecoder(r.Body).Decode(&resp)
		if err != nil {
			req.Message = "error parsing application/json: " + err.Error()
		} else {
				datauser := GetOneUserNPM(conn, colname, req.Data.UsernameId)
				req.Status = true
				req.Message = "data User berhasil diambil"
				req.Data = datauser
			}
		}
		return ReturnStringStruct(req)
	}

// Update User
func UpdateUser(Mongoenv, dbname string, r *http.Request) string {
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
		InsertUserdata(conn, userdata.UsernameId, userdata.Username, userdata.NPM, userdata.Password, hash, userdata.Email, userdata.Role)
		resp.Message = "Berhasil Input data"
	}
	response := ReturnStringStruct(resp)
	return response
}

// Delete User
func DeleteUser(Mongoenv, publickey, dbname, colname string, r *http.Request) string {
	resp := new(Cred)
	req := new(RequestUser)
	conn := GetConnectionMongo(Mongoenv, dbname)
	tokenlogin := r.Header.Get("Login")
	if tokenlogin == "" {
		resp.Status = fiber.StatusBadRequest
		resp.Message = "Token login tidak ada"
	} else {
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			resp.Message = "error parsing application/json: " + err.Error()
		} else {
			_, err := DeleteDataUser(conn, colname, req.NPM)
			if err != nil {
				resp.Status = fiber.StatusBadRequest
				resp.Message = "gagal hapus data"
			}
			resp.Status = fiber.StatusOK
			resp.Message = "data berhasil dihapus"
		}
	}
	return ReturnStringStruct(resp)
}

// Delete User
func GCFDeleteDataUser(Mongostring, dbname, colname string, r *http.Request) string {
	req := new(Credents)
	resp := new(User)
	conn := GetConnectionMongo(Mongostring, dbname)
	err := json.NewDecoder(r.Body).Decode(&resp)
	if err != nil {
		req.Status = strconv.Itoa(http.StatusNotFound)
		req.Message = "error parsing application/json: " + err.Error()
	} else {
		req.Status = strconv.Itoa(http.StatusOK)
		delResult, delErr := DeleteDataUser(conn, colname, resp.NPM)
		if delErr != nil {
			req.Status = strconv.Itoa(http.StatusInternalServerError)
			req.Message = "error deleting data: " + delErr.Error()
		} else {
			req.Message = fmt.Sprintf("Berhasil menghapus data. Jumlah data terhapus: %v", delResult.DeletedCount)
		}
	}
	return ReturnStringStruct(req)
}

// Update User
func GCFUpdateDataUser(Mongostring, dbname, colname string, r *http.Request) string {
	req := new(Credents)
	resp := new(User)
	conn := GetConnectionMongo(Mongostring, dbname)
	err := json.NewDecoder(r.Body).Decode(&resp)
	if err != nil {
		req.Status = strconv.Itoa(http.StatusNotFound)
		req.Message = "error parsing application/json: " + err.Error()
	} else {
		req.Status = strconv.Itoa(http.StatusOK)
		Ins := UpdateDataUser(conn, colname, resp.NPM, resp.Username, resp.Email, resp.Role)
		req.Message = fmt.Sprintf("%v:%v", "Berhasil Update data", Ins)
	}
	return ReturnStringStruct(req)
}
