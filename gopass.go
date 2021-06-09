package gopass

import (
	"encoding/base64"
	"golang.org/x/crypto/scrypt"
	"math/rand"
	"strconv"
	"time"
)

// generate salt string
func Salt() string {
	return strconv.Itoa(rand.New(rand.NewSource(time.Now().UnixNano())).Intn(100000000))
}

// generate salted password
func Generate(password string) (saltedPass, salt string, err error) {
	salt = Salt()
	dk, err := scrypt.Key([]byte(password), []byte(salt), 1<<15, 8, 1, 32)
	if err != nil {
		return
	}
	saltedPass = base64.StdEncoding.EncodeToString(dk)
	return
}

// compare password
func Compare(pass, customPass, salt string) bool {
	dk, err := scrypt.Key([]byte(customPass), []byte(salt), 1<<15, 8, 1, 32)
	if err != nil {
		return false
	}
	if base64.StdEncoding.EncodeToString(dk) != pass {
		return false
	}
	return true
}