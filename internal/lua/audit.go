package lua

import (
	"context"

	gopherlua "github.com/yuin/gopher-lua"

	auditctx "github.com/project-kessel/parsec/internal/audit"
)

// RegisterAuditService exposes the deployment-neutral audit reporter to Lua.
func RegisterAuditService(L *gopherlua.LState, ctx context.Context) {
	service := L.NewTable()
	service.RawSetString("record", L.NewFunction(func(state *gopherlua.LState) int {
		table, ok := state.Get(1).(*gopherlua.LTable)
		if !ok {
			state.Push(gopherlua.LFalse)
			return 1
		}
		validFields := map[string]bool{"source": true, "operation": true, "outcome": true, "reason_code": true, "classification": true, "metadata": true}
		unknown := false
		table.ForEach(func(key, _ gopherlua.LValue) {
			if key.Type() != gopherlua.LTString || !validFields[key.String()] {
				unknown = true
			}
		})
		if unknown {
			state.Push(gopherlua.LFalse)
			return 1
		}
		signal := auditctx.Signal{
			Source:         luaString(state.GetField(table, "source")),
			Operation:      luaString(state.GetField(table, "operation")),
			Outcome:        luaString(state.GetField(table, "outcome")),
			ReasonCode:     luaString(state.GetField(table, "reason_code")),
			Classification: luaString(state.GetField(table, "classification")),
			Metadata:       luaStringMap(state.GetField(table, "metadata")),
		}
		if !auditctx.Valid(signal) {
			state.Push(gopherlua.LFalse)
			return 1
		}
		auditctx.ReporterFrom(ctx).Record(signal)
		state.Push(gopherlua.LTrue)
		return 1
	}))
	L.SetGlobal("audit", service)
}

func luaString(value gopherlua.LValue) string {
	if value == gopherlua.LNil {
		return ""
	}
	return value.String()
}

func luaStringMap(value gopherlua.LValue) map[string]string {
	table, ok := value.(*gopherlua.LTable)
	if !ok || table == nil {
		return nil
	}
	result := make(map[string]string)
	table.ForEach(func(k, v gopherlua.LValue) {
		if k.Type() == gopherlua.LTString && v.Type() == gopherlua.LTString {
			result[k.String()] = v.String()
		}
	})
	if len(result) == 0 {
		return nil
	}
	return result
}
