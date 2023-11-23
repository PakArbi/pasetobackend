package pasetobackend

import (
	"golang.org/x/crypto/bcrypt"
	"regexp"
)

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func CheckEmailFormat(email string) bool {
	// Regular expression pattern for email validation including npm@std.ulbi.ac.id format
	emailRegexPattern := `^[a-zA-Z0-9._%+-]+@std\.ulbi\.ac\.id$`
	match, _ := regexp.MatchString(emailRegexPattern, email)
	return match
}


func CreateResponse(status bool, message string, data interface{}) Response {
	response := Response{
		Status:  status,
		Message: message,
		Data:    data,
	}
	return response
}
