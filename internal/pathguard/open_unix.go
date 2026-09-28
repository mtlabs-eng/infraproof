//go:build unix

package pathguard

import "syscall"

// nonBlocking keeps opening a path from becoming a wait.
//
// A named pipe with no writer blocks on open, before anything can look at what
// kind of file it is -- so a check that refuses a pipe never runs, and the
// server stops for as long as whoever placed it there cares to leave it. The
// flag makes the open return and the check happen.
const nonBlocking = syscall.O_NONBLOCK
