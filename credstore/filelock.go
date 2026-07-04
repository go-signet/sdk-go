package credstore

import (
	"errors"
	"fmt"
	"os"
	"time"
)

const (
	lockMaxRetries   = 50
	lockRetryDelay   = 100 * time.Millisecond
	staleLockTimeout = 30 * time.Second
)

// fileLock represents a file lock.
type fileLock struct {
	lockFile *os.File
	lockPath string
	// ownInfo identifies the lock file this holder created, captured at
	// acquire time. release uses it to avoid deleting a lock file that a
	// different process recreated after a stale-lock takeover.
	ownInfo os.FileInfo
}

// acquireFileLock acquires an exclusive lock on the token file.
// Uses a separate lock file to coordinate access across processes.
func acquireFileLock(filePath string) (*fileLock, error) {
	lockPath := filePath + ".lock"

	for range lockMaxRetries {
		lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			info, _ := lockFile.Stat() // identity of the file we just created
			return &fileLock{
				lockFile: lockFile,
				lockPath: lockPath,
				ownInfo:  info,
			}, nil
		}

		if os.IsExist(err) {
			if info, statErr := os.Stat(lockPath); statErr == nil {
				if time.Since(info.ModTime()) > staleLockTimeout {
					if remErr := os.Remove(lockPath); remErr != nil && !os.IsNotExist(remErr) {
						return nil, fmt.Errorf(
							"failed to remove stale lock file %s: %w",
							lockPath,
							remErr,
						)
					}
					continue
				}
			}
			time.Sleep(lockRetryDelay)
			continue
		}

		return nil, fmt.Errorf("failed to acquire file lock: %w", err)
	}

	return nil, fmt.Errorf(
		"timeout waiting for file lock after %v",
		time.Duration(lockMaxRetries)*lockRetryDelay,
	)
}

// release releases the file lock. When this holder's identity was captured at
// acquire time (ownInfo set), it removes the lock file only if the file still
// on disk is the one it created: if our critical section stalled past
// staleLockTimeout, another process may have removed our lock as stale and
// created its own at the same path, and deleting that file would break the new
// holder's mutual exclusion. When the identity could not be captured (the
// acquire-time Stat failed), it falls back to an unconditional remove. This
// narrows but does not eliminate the race — a takeover landing between the Stat
// and Remove can still occur — so lockfile-based exclusion under a wall-clock
// stale timeout remains best-effort.
func (fl *fileLock) release() error {
	var closeErr error
	if fl.lockFile != nil {
		closeErr = fl.lockFile.Close()
	}

	var removeErr error
	if fl.ownInfo == nil {
		// Identity unknown — fall back to the prior unconditional remove.
		removeErr = os.Remove(fl.lockPath)
	} else if onDisk, statErr := os.Stat(fl.lockPath); statErr == nil &&
		os.SameFile(fl.ownInfo, onDisk) {
		// Still our file. If a different process recreated the lock after a
		// stale takeover, SameFile is false and we leave its lock intact.
		removeErr = os.Remove(fl.lockPath)
	}
	return errors.Join(closeErr, removeErr)
}
