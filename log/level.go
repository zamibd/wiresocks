package log

import (
	"log/slog"
)

// Level is an alias for slog.Level.
type Level = slog.Level

// Levels are aliases for Level.
const (
	DebugLevel  = slog.LevelDebug
	InfoLevel   = slog.LevelInfo
	WarnLevel   = slog.LevelWarn
	ErrorLevel  = slog.LevelError
	SilentLevel = slog.LevelError + 1 // Custom level for silent
)

// ParseLevel is a thin wrapper for slog.ParseLevel.
func ParseLevel(text string) (Level, error) {
	switch text {
	case "silent", "SILENT":
		return SilentLevel, nil
	default:
		var level slog.Level
		err := level.UnmarshalText([]byte(text))
		return level, err
	}
}
