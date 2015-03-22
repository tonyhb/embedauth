package auth

import (
	"bytes"
	"testing"

	"github.com/tonyhb/govalidate/rules/uuid"
)

func init() {
	// Lower the hash cost for testing
	HashCost = 1
}

func TestNewActivationKey(t *testing.T) {
	a := &Auth{}
	a.NewActivationKey()
	if !uuid.IsUUID(string(a.ActivationKey)) {
		t.Fatal()
	}
	if a.ActivationExpires.IsZero() {
		t.Fatal()
	}
}

func TestActivate(t *testing.T) {
	a := &Auth{}
	// Without an activation key set this should fail: time.Now() is always
	// after a zero time.
	if err := a.Activate([]byte{}); err != ErrActivationKeyExpired {
		t.Fatal()
	}
	// Even though an activation key hasn't been set we can ensure we check
	// the key matches
	if err := a.Activate([]byte("test")); err != ErrInvalidActivationKey {
		t.Fatal()
	}

	a.NewActivationKey()

	// Incorrect key
	if err := a.Activate([]byte{}); err != ErrInvalidActivationKey {
		t.Fatal()
	}
	// Even though an activation key hasn't been set we can ensure we check
	// the key matches
	if err := a.Activate(a.ActivationKey); err != nil {
		t.Fatal(err.Error())
	}

	if !a.IsActive {
		t.Fatal()
	}
}

func TestNewResetKey(t *testing.T) {
	a := &Auth{}
	a.NewResetKey()
	if !uuid.IsUUID(string(a.ResetKey)) {
		t.Fatal()
	}
	if a.ResetExpires.IsZero() {
		t.Fatal()
	}
}

func TestSetPassword(t *testing.T) {
	a := &Auth{}
	a.SetPassword([]byte("test"))
	assertPassword(a, t)

	if err := a.SetPassword([]byte{}); err == nil {
		t.Fatal()
	}
}

func TestSetPasswordString(t *testing.T) {
	a := &Auth{}
	a.SetPasswordString("test")
	assertPassword(a, t)

	if err := a.SetPasswordString(""); err == nil {
		t.Fatal()
	}
}

// This is the logic for asserting that a password is set correctly
func assertPassword(a *Auth, t *testing.T) {
	if len(a.PasswordHash) != 60 {
		t.Fatal()
	}
	if !bytes.Equal(a.PasswordHash[0:7], []byte("$2a$10$")) {
		t.Fatal()
	}
	if !uuid.IsUUID(string(a.PasswordSalt)) {
		t.Fatal()
	}
}

func TestComparePassword(t *testing.T) {
	a := &Auth{}
	pw := []byte("test")
	a.SetPassword(pw)
	if a.ComparePassword([]byte("fail")) == nil {
		t.Fatal()
	}
	if a.ComparePassword(pw) != nil {
		t.Fatal()
	}
}

func TestComparePasswordString(t *testing.T) {
	a := &Auth{}
	pw := []byte("test")
	a.SetPassword(pw)
	if a.ComparePasswordString("fail") == nil {
		t.Fatal()
	}
	if a.ComparePasswordString(string(pw)) != nil {
		t.Fatal()
	}
}
