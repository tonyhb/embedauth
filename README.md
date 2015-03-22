# EmbedAuth

A small struct which may be anonymously embedded into your User struct in go for
authentication. 

## Why?

This aims to save you time writing auth methods over and over.

Auth isn't so hard to write in go. You wrap bycrypt to set and validate
passwords, and you create a reset password/confirm account key randomly.

Thing is, you don't want to write this each time you have a project.

## Show me how to use it!

Alrighty. Check this code out:

```go
type User struct {
	Id int64

	// Include the auth struct anonymously. This allows you to access all auth
	// methods in your user struct directly
	embedauth.Auth
}
```

## But dude, now my JSON represnetation of User is too wild.

Yeah, that can be a little annoying. But wait, you're probably already using an
auxiliary data structure to marshal your user, right? Let's sort that out now:

```go

type User struct{
	Id int64
	embedauth.Auth
}

// When marshalling to JSON we only want to show our "id" and "email" fields.
// We also don't want embedauth to be a sub-object. To do this we'll marshal
// from an aux struct.
func (u User) MarshalJSON() ([]byte, error) {
	var aux struct {
		Id    int64  `json:"id"`
		Email string `json:"email"`
	}

	aux.Id, aux.Email = u.Id, u.Email
	return json.Marshal(aux)
}
```
