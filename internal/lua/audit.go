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
		validFields := map[string]bool{"source": true, "operation": true, "outcome": true, "reason_code": true, "classification": true, "event": true, "metadata": true}
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
		metadata, metadataValid := luaStringMap(state.GetField(table, "metadata"))
		if !metadataValid {
			// Metadata is not a table, or has a non-string key or a value
			// that is not a string, number or boolean; reject entire signal
			state.Push(gopherlua.LFalse)
			return 1
		}
		signal := auditctx.Signal{
			Source:         luaString(state.GetField(table, "source")),
			Operation:      luaString(state.GetField(table, "operation")),
			Outcome:        luaString(state.GetField(table, "outcome")),
			ReasonCode:     luaString(state.GetField(table, "reason_code")),
			Classification: luaString(state.GetField(table, "classification")),
			Event:          luaString(state.GetField(table, "event")),
			Metadata:       metadata,
		}
		// The reporter sanitizes, strips disallowed metadata keys and
		// validates. Checking here first would reject signals that stripping
		// makes valid, and would hide rejections from the request record.
		if auditctx.ReporterFrom(ctx).Record(signal) {
			state.Push(gopherlua.LTrue)
		} else {
			state.Push(gopherlua.LFalse)
		}
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

// luaStringMap converts a Lua table to a map[string]string, returning both the
// result and a validity flag. Number and boolean values are converted to
// their string form: a script passing a raw id or flag must not lose the whole
// signal. Returns (nil, false) for a non-string key or any other value type,
// preventing silent skipping of invalid metadata entries.
func luaStringMap(value gopherlua.LValue) (map[string]string, bool) {
	if value == nil || value == gopherlua.LNil {
		return nil, true // nil metadata is valid (absent)
	}
	table, ok := value.(*gopherlua.LTable)
	if !ok {
		return nil, false // non-table metadata is invalid
	}
	result := make(map[string]string)
	allValid := true
	table.ForEach(func(k, v gopherlua.LValue) {
		if k.Type() != gopherlua.LTString {
			allValid = false
			return
		}
		switch v.Type() {
		case gopherlua.LTString, gopherlua.LTNumber, gopherlua.LTBool:
			result[k.String()] = v.String()
		default:
			allValid = false
		}
	})
	if !allValid {
		return nil, false
	}
	if len(result) == 0 {
		return nil, true // empty metadata is valid
	}
	return result, true
}
