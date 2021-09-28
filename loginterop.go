package main

import (
	"encoding/json"
	"fmt"
	glog "github.com/ethereum/go-ethereum/log"
	"github.com/sirupsen/logrus"
	"reflect"
)

type GethLogger struct {
	logrus.FieldLogger

	// adjust log level down/up, geth can be verbose
	Adjust int
}

type LazyLogEntry glog.Lazy

// From the Geth source, since it's not accessible and we somehow need to get the log values.
func evaluateLazy(lz glog.Lazy) (interface{}, error) {
	t := reflect.TypeOf(lz.Fn)

	if t.Kind() != reflect.Func {
		return nil, fmt.Errorf("INVALID_LAZY, not func: %+v", lz.Fn)
	}

	if t.NumIn() > 0 {
		return nil, fmt.Errorf("INVALID_LAZY, func takes args: %+v", lz.Fn)
	}

	if t.NumOut() == 0 {
		return nil, fmt.Errorf("INVALID_LAZY, no func return val: %+v", lz.Fn)
	}

	value := reflect.ValueOf(lz.Fn)
	results := value.Call([]reflect.Value{})
	if len(results) == 1 {
		return results[0].Interface(), nil
	}
	values := make([]interface{}, len(results))
	for i, v := range results {
		values[i] = v.Interface()
	}
	return values, nil
}

func (lle LazyLogEntry) MarshalJSON() ([]byte, error) {
	dat, err := evaluateLazy((glog.Lazy)(lle))
	if err != nil {
		return nil, err
	}
	return json.Marshal(dat)
}

func (lle LazyLogEntry) MarshalText() ([]byte, error) {
	dat, err := evaluateLazy((glog.Lazy)(lle))
	if err != nil {
		return nil, err
	}
	return json.Marshal(dat)
}

// New returns a new Logger that has this logger's context plus the given context
func (gl GethLogger) Log(r *glog.Record) error {
	rCtx := r.Ctx
	l := gl.FieldLogger
	for i := 0; i < len(rCtx); i += 2 {
		val := rCtx[i+1]
		if inner, ok := val.(glog.Lazy); ok {
			val = LazyLogEntry(inner)
		}
		l = l.WithField(rCtx[i].(string), val)
	}

	lvl := r.Lvl + glog.Lvl(gl.Adjust)
	if lvl < glog.LvlCrit {
		lvl = glog.LvlCrit
	}
	if lvl > glog.LvlTrace {
		lvl = glog.LvlTrace
	}
	switch lvl {
	case glog.LvlCrit:
		l.Panicln(r.Msg)
	case glog.LvlError:
		l.Errorln(r.Msg)
	case glog.LvlWarn:
		l.Warningln(r.Msg)
	case glog.LvlInfo:
		l.Infoln(r.Msg)
	case glog.LvlDebug:
		l.Debugln(r.Msg)
	case glog.LvlTrace:
		l.Debugln(r.Msg)
	}
	return nil
}
