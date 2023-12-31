package pasetobackend

import "time"

type User struct {
	UsernameId   string `json:"usernameid" bson:"usernameid"`
	Username     string `json:"username" bson:"username"`
	NPM          string `json:"npm" bson:"npm"`
	Password     string `json:"password" bson:"password"`
	PasswordHash string `json:"passwordhash" bson:"passwordhash"`
	Email        string `bson:"email,omitempty" json:"email,omitempty"`
	Role         string `json:"role,omitempty" bson:"role,omitempty"`
	Token        string `json:"token,omitempty" bson:"token,omitempty"`
	Private      string `json:"private,omitempty" bson:"private,omitempty"`
	Public       string `json:"public,omitempty" bson:"public,omitempty"`
}

type Admin struct {
	Username     string `json:"username" bson:"username"`
	Password     string `json:"password" bson:"password"`
	PasswordHash string `json:"passwordhash" bson:"passwordhash"`
	Email        string `bson:"email,omitempty" json:"email,omitempty"`
	Role         string `json:"role,omitempty" bson:"role,omitempty"`
	Token        string `json:"token,omitempty" bson:"token,omitempty"`
	Private      string `json:"private,omitempty" bson:"private,omitempty"`
	Public       string `json:"public,omitempty" bson:"public,omitempty"`
}

type Credential struct {
	Status  bool   `json:"status" bson:"status"`
	Token   string `json:"token,omitempty" bson:"token,omitempty"`
	Message string `json:"message,omitempty" bson:"message,omitempty"`
}

type Credents struct {
	Status  string `json:"status" bson:"status"`
	Token   string `json:"token,omitempty" bson:"token,omitempty"`
	Message string `json:"message" bson:"message"`
}

type Cred struct {
	Status  int    `json:"status"`
	Message string `json:"message"`
}

type Response struct {
	Status  bool   `json:"status" bson:"status"`
	Message string `json:"message" bson:"message"`
	Data    []User `json:"data" bson:"data"`
	// Data    interface{} `json:"data" bson:"data"`
}

type ResponseUser struct {
	Status  bool   `json:"status" bson:"status"`
	Message string `json:"message" bson:"message"`
	Data    User   `json:"data" bson:"data"`
	// Data    interface{} `json:"data" bson:"data"`
}

type ResponseGet struct {
	Token string `json:"token,omitempty" bson:"token,omitempty"`
}

type RequestUser struct {
	NPM string `json:"npm" bson:"npm"`
}

// EmailValidator adalah tipe khusus untuk validasi email npm@std.ulbi.ac.id
type EmailValidator struct {
	regexPattern string
}

type Payload struct {
	User string    `json:"user"`
	Role string    `json:"role"`
	Exp  time.Time `json:"exp"`
	Iat  time.Time `json:"iat"`
	Nbf  time.Time `json:"nbf"`
}

type ResponseEncode struct {
	Message string `json:"message,omitempty" bson:"message,omitempty"`
	Token   string `json:"token,omitempty" bson:"token,omitempty"`
}
