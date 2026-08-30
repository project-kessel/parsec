package lua

import (
	"github.com/project-kessel/parsec/internal/clock"
	lua "github.com/yuin/gopher-lua"
)

// ClockService provides time functions to Lua scripts.
type ClockService struct {
	clock clock.Clock
}

// NewClockService creates a clock service backed by the given clock.
func NewClockService(clk clock.Clock) *ClockService {
	if clk == nil {
		clk = clock.NewSystemClock()
	}
	return &ClockService{clock: clk}
}

// Register adds now_ms() as a global function in the Lua state.
func (s *ClockService) Register(L *lua.LState) {
	L.SetGlobal("now_ms", L.NewFunction(s.luaNowMs))
}

func (s *ClockService) luaNowMs(L *lua.LState) int {
	L.Push(lua.LNumber(s.clock.Now().UnixMilli()))
	return 1
}
