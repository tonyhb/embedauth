package auth

import (
	"bytes"
	"fmt"
	"time"

	"code.google.com/p/go-uuid/uuid"
	"golang.org/x/crypto/bcrypt"
)

var (
	// This is the cost of bcrypt hashing
	HashCost = 15

	// Update this within your code to set the minimum password length requirements
	MinPasswordLength = 8

	ErrActivationKeyExpired = fmt.Errorf("Activation key expired")
	ErrInvalidActivationKey = fmt.Errorf("Activation key is invalid")
)

type Auth struct {
	Email        string `validate:"Email"`
	PasswordHash []byte `validate:"NotEmpty" db:"password_hash"`
	PasswordSalt []byte `db:"password_salt"`

	IsActive          bool      `db:"is_active"`
	ActivationKey     []byte    `db:"activation_key"`
	ActivationExpires time.Time `db:"activation_expires"`

	ResetKey     []byte    `db:"reset_key"`
	ResetExpires time.Time `db:"reset_expires"`
}

// Generates a new activation key for the
func (a *Auth) NewActivationKey() {
	a.ActivationKey = []byte(uuid.New())
	a.ActivationExpires = time.Now().AddDate(0, 0, 7)
}

func (a *Auth) NewResetKey() {
	a.ResetKey = []byte(uuid.New())
	a.ResetExpires = time.Now().AddDate(0, 0, 7)
}

// Activates a user if the activation expiry has not passed. This also empties
// the activation key
func (a *Auth) Activate(key []byte) error {
	if !bytes.Equal(a.ActivationKey, key) {
		return ErrInvalidActivationKey
	}

	if time.Now().After(a.ActivationExpires) {
		return ErrActivationKeyExpired
	}

	a.IsActive = true
	a.ActivationKey = nil
	return nil
}

func (a *Auth) SetPassword(pw []byte) error {
	a.PasswordSalt = []byte(uuid.New())

	if len(pw) == 0 {
		return fmt.Errorf("A password must be provided")
	}

	if len(pw) < MinPasswordLength {
		return fmt.Errorf("Passwords must be %d characters long", MinPasswordLength)
	}

	hash, err := bcrypt.GenerateFromPassword(a.addSaltToPassword(pw), HashCost)
	if err != nil {
		return err
	}

	a.PasswordHash = hash
	return nil
}

func (a *Auth) SetPasswordString(pw string) error {
	return a.SetPassword([]byte(pw))
}

// Compares a given password to the stored user password. Returns nil if the
// passwords match
func (a *Auth) ComparePassword(pw []byte) error {
	return bcrypt.CompareHashAndPassword(a.PasswordHash, a.addSaltToPassword(pw))
}

func (a *Auth) ComparePasswordString(pw string) error {
	return a.ComparePassword([]byte(pw))
}

// Concatenates a password with the user's salt
func (a *Auth) addSaltToPassword(pw []byte) []byte {
	return bytes.Join([][]byte{pw, a.PasswordSalt}, nil)
}
