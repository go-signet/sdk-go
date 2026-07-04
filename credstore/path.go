package credstore

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// DefaultStorePath returns a conventional, OS-appropriate path for storing
// credentials at filepath.Join(dir, appName, fileName), where dir is the
// user's config directory as reported by os.UserConfigDir:
//
//   - macOS:   ~/Library/Application Support
//   - Linux:   $XDG_CONFIG_HOME, else ~/.config
//   - Windows: %AppData%
//
// appName and fileName must be non-empty. The parent directories are not
// created here; the file-backed stores create them on first Save.
//
// Pass the result straight into DefaultTokenSecureStore or DefaultSecureStore:
//
//	path, err := credstore.DefaultStorePath("my-app", "tokens.json")
//	if err != nil {
//		return err
//	}
//	store := credstore.DefaultTokenSecureStore("my-app", path)
func DefaultStorePath(appName, fileName string) (string, error) {
	if appName == "" {
		return "", errors.New("credstore: appName cannot be empty")
	}
	if fileName == "" {
		return "", errors.New("credstore: fileName cannot be empty")
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("failed to resolve user config dir: %w", err)
	}
	return filepath.Join(dir, appName, fileName), nil
}

// DefaultTokenFileName is the conventional file name used by DefaultTokenStorePath.
const DefaultTokenFileName = "tokens.json"

// DefaultTokenStorePath is a shorthand for DefaultStorePath(appName,
// DefaultTokenFileName) — the conventional path for an app's token file. Pass
// the result straight into DefaultTokenSecureStore:
//
//	path, err := credstore.DefaultTokenStorePath("my-app")
//	if err != nil {
//		return err
//	}
//	store := credstore.DefaultTokenSecureStore("my-app", path)
func DefaultTokenStorePath(appName string) (string, error) {
	return DefaultStorePath(appName, DefaultTokenFileName)
}
