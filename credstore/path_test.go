package credstore_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/go-signet/sdk-go/credstore"
)

func TestDefaultStorePath(t *testing.T) {
	dir, err := os.UserConfigDir()
	if err != nil {
		t.Skipf("user config dir unavailable: %v", err)
	}

	got, err := credstore.DefaultStorePath("my-app", "tokens.json")
	if err != nil {
		t.Fatalf("DefaultStorePath() error = %v", err)
	}

	want := filepath.Join(dir, "my-app", "tokens.json")
	if got != want {
		t.Errorf("DefaultStorePath() = %q, want %q", got, want)
	}
}

func TestDefaultTokenStorePath(t *testing.T) {
	dir, err := os.UserConfigDir()
	if err != nil {
		t.Skipf("user config dir unavailable: %v", err)
	}

	got, err := credstore.DefaultTokenStorePath("my-app")
	if err != nil {
		t.Fatalf("DefaultTokenStorePath() error = %v", err)
	}

	want := filepath.Join(dir, "my-app", credstore.DefaultTokenFileName)
	if got != want {
		t.Errorf("DefaultTokenStorePath() = %q, want %q", got, want)
	}
}

func TestDefaultTokenStorePath_EmptyAppName(t *testing.T) {
	if _, err := credstore.DefaultTokenStorePath(""); err == nil {
		t.Error("DefaultTokenStorePath(\"\") error = nil, want error")
	}
}

func TestDefaultStorePath_Validation(t *testing.T) {
	tests := []struct {
		name     string
		appName  string
		fileName string
	}{
		{name: "empty appName", appName: "", fileName: "tokens.json"},
		{name: "empty fileName", appName: "my-app", fileName: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := credstore.DefaultStorePath(tt.appName, tt.fileName); err == nil {
				t.Errorf(
					"DefaultStorePath(%q, %q) error = nil, want error",
					tt.appName,
					tt.fileName,
				)
			}
		})
	}
}
