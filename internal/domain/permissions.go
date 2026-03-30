package domain

type Permissions uint8

const (
	CanEditTitle Permissions = 1 << iota
	CanEditPublishers
	CanEditPlatforms
	CanEditGenres
	CanEditUsers
)
