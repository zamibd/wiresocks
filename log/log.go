package log

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"sync"
	"time"
)

// global Logger
var (
	_globalMu sync.RWMutex
	_globalL  *slog.Logger
)

func init() {
	SetLogger(slog.Default())
}

func NewLeveled(l Level) (*slog.Logger, error) {
	handlerOptions := &slog.HandlerOptions{
		AddSource: true,
		Level:     l,
	}

	return slog.New(slog.NewTextHandler(os.Stderr, handlerOptions)), nil
}

// SetLogger sets the global Logger.
func SetLogger(logger *slog.Logger) {
	_globalMu.Lock()
	defer _globalMu.Unlock()
	_globalL = logger
}

func logf(lvl Level, template string, args ...any) {
	_globalMu.RLock()
	l := _globalL
	_globalMu.RUnlock()

	if !l.Enabled(context.Background(), lvl) {
		return
	}

	var pcs [1]uintptr
	runtime.Callers(3, pcs[:]) // skip [Callers, logf, Debugf/Infof/etc.]

	r := slog.NewRecord(time.Now(), lvl, fmt.Sprintf(template, args...), pcs[0])
	_ = l.Handler().Handle(context.Background(), r)
}

func Debugf(template string, args ...any) {
	logf(DebugLevel, template, args...)
}

func Infof(template string, args ...any) {
	logf(InfoLevel, template, args...)
}

func Warnf(template string, args ...any) {
	logf(WarnLevel, template, args...)
}

func Errorf(template string, args ...any) {
	logf(ErrorLevel, template, args...)
}

func Fatalf(template string, args ...any) {
	logf(slog.LevelError, template, args...)
	os.Exit(1)
}
