package pasetobackend

import (
	"golang.org/x/crypto/bcrypt"
	"regexp"
)

func HashPassword(passwordhash string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(passwordhash), 14)
	return string(bytes), err
}

func CheckPasswordHash(passwordhash, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(passwordhash))
	return err == nil
}

// func CreateResponse(status bool, message string, data interface{}) Response {
// 	response := Response{
// 		Status:  status,
// 		Message: message,
// 		Data:    data,
// 	}
// 	return response
// }

//check email @std.ulbi.ac.id
func CheckEmail(email string) bool {
	emailRegex := `^[a-zA-Z0-9._%+-]+@std.ulbi.ac.id$`
	match, _ := regexp.MatchString(emailRegex, email)
	return match
}