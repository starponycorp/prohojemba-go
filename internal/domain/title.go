package domain

type TitleType uint8

const (
	Game TitleType = iota
	Film
	Book
)

type Title struct {
	Id       uint
	Name     string
	CoverUrl string
	Type     TitleType
	Tags     []Tag
	Status   TitleState
}
