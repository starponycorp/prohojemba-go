package domain

type User struct {
	Id             uint
	Username       string
	ViewName       string
	HashedPassword string
	Permissions    Permissions
}
