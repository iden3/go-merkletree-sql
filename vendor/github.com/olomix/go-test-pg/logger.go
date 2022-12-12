package go_test_pg

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v4"
)

func newLogger(t testing.TB) logger {
	return logger{t: t}
}

type logger struct {
	t testing.TB
}

func (l logger) Log(ctx context.Context, level pgx.LogLevel, msg string,
	data map[string]interface{}) {
	if len(data) > 0 {
		params := make([]string, 0, len(data))
		for k, v := range data {
			params = append(params, fmt.Sprintf("%v: %v", k, v))
		}
		l.t.Logf("%v (%v)", msg, strings.Join(params, ", "))
	} else {
		l.t.Log(msg)
	}
}
