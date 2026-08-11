package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Every field the schema declares must be readable from a file.
//
// The loader ends in "ignore unknown keys", so a field added to the struct
// without a matching case is written by the console, accepted by validation, and
// then does nothing — which is how ws_path, ws_host and low_latency came to be
// configured and ignored for several releases. This walks the struct tags so a
// new field cannot be added without wiring it up.
func TestEveryConfigFieldIsReadable(t *testing.T) {
	rt := reflect.TypeOf(Config{})
	dir := t.TempDir()
	for i := 0; i < rt.NumField(); i++ {
		key := rt.Field(i).Tag.Get("toml")
		if key == "" {
			continue
		}
		var line string
		switch rt.Field(i).Type.Kind() {
		case reflect.String:
			line = key + ` = "x"`
		case reflect.Int:
			line = key + " = 1"
		case reflect.Bool:
			line = key + " = true"
		case reflect.Slice:
			line = key + ` = ["x"]`
		default:
			t.Fatalf("field %s has an unhandled kind %s", key, rt.Field(i).Type.Kind())
		}
		path := filepath.Join(dir, "t.toml")
		if err := os.WriteFile(path, []byte(line+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		c, err := LoadRelaxed(path)
		if err != nil {
			t.Fatalf("%s: %v", key, err)
		}
		if u := c.Unknown(); len(u) > 0 {
			t.Errorf("%q is in the schema but the loader ignores it — it would be written and silently do nothing", key)
		}
	}
}

// An unrecognised key must be reported rather than dropped.
func TestUnknownKeysAreReported(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "t.toml")
	body := "name = \"x\"\nnot_a_real_option = 5\nalso_bogus = \"y\"\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadRelaxed(path)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(c.Unknown(), ",")
	if got != "not_a_real_option,also_bogus" {
		t.Fatalf("unknown keys reported as %q", got)
	}
}
