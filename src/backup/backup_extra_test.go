package backup

import (
	"archive/tar"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// errWriter is an io.Writer that always returns an error after the first write.
type errWriter struct {
	n int
}

func (e *errWriter) Write(p []byte) (int, error) {
	if e.n > 0 {
		return 0, io.ErrClosedPipe
	}
	e.n++
	return len(p), nil
}

// TestAddFileToTar_WriteHeaderError exercises the WriteHeader error branch (line 293).
func TestAddFileToTar_WriteHeaderError(t *testing.T) {
	// Wrap an errWriter so tw.WriteHeader fails on the first call.
	tw := tar.NewWriter(&errWriter{})
	err := addFileToTar(tw, "test.txt", []byte("hello"))
	if err == nil {
		t.Fatal("expected error from broken tar writer, got nil")
	}
}

// TestAddFileToTar_WriteDataError exercises the tw.Write error branch (line 296).
// We need WriteHeader to succeed but Write to fail.
// A successful header write requires the writer to accept the header bytes;
// we use a real in-memory buffer for the first write and then fail.
func TestAddFileToTar_WriteDataError(t *testing.T) {
	// Use a pipe: close the write-end after 512 bytes (one tar block = one header)
	// so the data write fails.
	pr, pw := io.Pipe()
	defer pr.Close()

	// Drain the reader in a goroutine so WriteHeader can complete, then close
	// the write-end to cause subsequent writes to fail.
	headerDone := make(chan struct{})
	go func() {
		buf := make([]byte, 512)
		_, _ = io.ReadFull(pr, buf) // drain one 512-byte block (header)
		close(headerDone)
		pr.CloseWithError(io.ErrClosedPipe)
	}()

	tw := tar.NewWriter(pw)
	// Use a non-empty payload so tar actually tries to write data after the header.
	err := addFileToTar(tw, "test.txt", []byte("hello world"))
	<-headerDone
	_ = pw.Close()
	if err == nil {
		t.Fatal("expected error when data write fails, got nil")
	}
}

// TestCopyFile_NonExistentSource exercises the os.Open error branch in copyFile.
func TestCopyFile_NonExistentSource(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "no-such-file.txt")
	dst := filepath.Join(dir, "dst.txt")
	err := copyFile(src, dst)
	if err == nil {
		t.Fatal("expected error when source does not exist, got nil")
	}
}

// TestCopyFile_UnwritableDestDir exercises the os.MkdirAll error branch.
// We place a regular file where the destination directory should be, making
// MkdirAll fail because the path is occupied by a file.
func TestCopyFile_UnwritableDestDir(t *testing.T) {
	dir := t.TempDir()

	// Create a real source file.
	src := filepath.Join(dir, "src.txt")
	if err := os.WriteFile(src, []byte("data"), 0600); err != nil {
		t.Fatalf("write src: %v", err)
	}

	// Block the destination parent directory by putting a regular file there.
	blockDir := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blockDir, []byte("I am a file"), 0600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}

	// dst path requires blockDir to be a directory — MkdirAll will fail.
	dst := filepath.Join(blockDir, "subdir", "dst.txt")
	err := copyFile(src, dst)
	if err == nil {
		t.Fatal("expected error when destination directory cannot be created, got nil")
	}
}

// TestCopyFile_Success exercises the happy path of copyFile end-to-end, covering
// the Stat + Chmod statements (lines 345-351).
func TestCopyFile_Success(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.txt")
	dst := filepath.Join(dir, "dst.txt")

	content := []byte("hello copy")
	if err := os.WriteFile(src, content, 0644); err != nil {
		t.Fatalf("write src: %v", err)
	}

	if err := copyFile(src, dst); err != nil {
		t.Fatalf("copyFile() error = %v", err)
	}

	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read dst: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("dst content = %q, want %q", got, content)
	}
}

// TestAddPathToTar_MissingFile exercises the os.Open error branch in addPathToTar.
func TestAddPathToTar_MissingFile(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	var contents []string
	err := addPathToTar(tw, t.TempDir(), "nonexistent.txt", &contents)
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}
