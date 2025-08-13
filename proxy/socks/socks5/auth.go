package socks5

// CredentialStore is an interface for storing and validating user credentials.
type CredentialStore interface {
	Valid(user, password string) bool
}

// StaticCredentials stores a map of username to password.
type StaticCredentials map[string]string

// Valid checks if the given user and password are valid.
func (s StaticCredentials) Valid(user, password string) bool {
	pass, ok := s[user]
	if !ok {
		return false
	}
	return pass == password
}
