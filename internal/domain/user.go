package domain

type Permissions uint8

const (
	CanEditTitle Permissions = 1 << iota
	CanEditPublishers
	CanEditPlatforms
	CanEditGenres
	CanEditUsers
)

type User struct {
	Id             uint
	Username       string
	ViewName       string
	HashedPassword string
	Permissions    Permissions
}
