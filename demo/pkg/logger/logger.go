package logger

import (
	"github.com/gookit/color"
)

var (
	Red		   = color.Red.Render
	Cyan       = color.Cyan.Render
	Yellow     = color.Yellow.Render
	White      = color.White.Render
	Blue       = color.Blue.Render
	Purple     = color.Style{color.Magenta, color.OpBold}.Render
	LightRed   = color.Style{color.Red, color.OpBold}.Render
	LightGreen = color.Style{color.Green, color.OpBold}.Render
	LightWhite = color.Style{color.White, color.OpBold}.Render
	LightCyan  = color.Style{color.Cyan, color.OpBold}.Render
	LightYellow  = color.Style{color.Yellow, color.OpBold}.Render
	LightBlue  = color.Style{color.Blue, color.OpBold}.Render
)

