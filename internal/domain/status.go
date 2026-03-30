package domain

type TitleState uint8

const (
	None TitleState = iota
	Planned
	InProgress
	Abandoned
	Completed
)
