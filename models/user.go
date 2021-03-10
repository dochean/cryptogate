package models

import "strings"

type Auth interface {
	Authenticate() bool
}

type Account struct {
	Name string
	Passwd string
}

// Authenticate check passwd(bcrypt or other), not implemented now
func (a *Account) Authenticate() bool {
	if len(strings.TrimSpace(a.Name))==0 || len(strings.TrimSpace(a.Passwd)) == 0 {
		return false
	}

	return true
}