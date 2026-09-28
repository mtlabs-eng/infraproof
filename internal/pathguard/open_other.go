//go:build !unix

package pathguard

// nonBlocking has no equivalent here. Opening a path on this platform does not
// wait on a writer, so there is nothing to ask for.
const nonBlocking = 0
