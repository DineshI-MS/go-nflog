//go:build linux
// +build linux

package nflog

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestOpen(t *testing.T) {
	tests := []struct {
		name     string
		group    uint16
		copymode uint8
		err      error
		flags    uint16
	}{
		{name: "InvalidCopymode", copymode: 0x5, err: ErrCopyMode},
		{name: "InvalidFlags", flags: 0x5, err: ErrUnknownFlag},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			config := Config{
				Copymode: tc.copymode,
				Group:    tc.group,
				Flags:    tc.flags,
			}
			_, err := Open(&config)
			if err != tc.err {
				t.Fatalf("Unexpected error - want: %v\tgot: %v\n", tc.err, err)
			}
		})
	}
}

func TestSockBufSize(t *testing.T) {
	// Skip if not root
	if os.Getuid() != 0 {
		t.Skip("Test requires root privileges")
	}

	config := &Config{
		Group:       1,
		Copymode:    CopyPacket,
		SockBufSize: 2097152, // 2MB
	}

	nf, err := Open(config)
	if err != nil {
		t.Fatalf("failed to open nflog: %v", err)
	}
	defer nf.Close()

	// Verify buffer size was applied
	rawConn, err := nf.Con.SyscallConn()
	if err != nil {
		t.Fatalf("failed to get raw connection: %v", err)
	}

	var bufsize int
	var sockErr error
	err = rawConn.Control(func(fd uintptr) {
		bufsize, sockErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF)
	})
	if err != nil {
		t.Fatalf("failed to control socket: %v", err)
	}
	if sockErr != nil {
		t.Fatalf("failed to get socket buffer size: %v", sockErr)
	}

	// Linux doubles the value internally, so we check if it's at least our requested size
	if bufsize < int(config.SockBufSize) {
		t.Errorf("socket buffer size not applied correctly: got %d, want at least %d",
			bufsize, config.SockBufSize)
	}
}

func TestSockBufSizeDefault(t *testing.T) {
	config := &Config{
		Group:       1,
		Copymode:    CopyPacket,
		SockBufSize: 0,
	}

	nf, err := Open(config)
	if err != nil {
		t.Fatalf("failed to open nflog with default socket buffer: %v", err)
	}
	defer nf.Close()
}
