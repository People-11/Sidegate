package main

// C ABI for the Rust GUI. Rust owns the process; we just run goroutines inside it.

// #include <stdlib.h>
import "C"

import (
	"sync"
	"unsafe"
)

var (
	cmds   = make(chan string, 16)
	events = make(chan string, 64)
	start  sync.Once
)

//export GpSend
func GpSend(cmd *C.char) {
	start.Do(func() { go serveCommands(cmds) })
	cmds <- C.GoString(cmd)
}

// GpRecv blocks for the next event line. Free the result with GpFree.
//
//export GpRecv
func GpRecv() *C.char {
	start.Do(func() { go serveCommands(cmds) })
	return C.CString(<-events)
}

//export GpFree
func GpFree(p *C.char) { C.free(unsafe.Pointer(p)) }

// GpCallback is the "--callback <url>" mode the browser launches for globalprotectcallback: links.
//
//export GpCallback
func GpCallback(url *C.char) { deliverCallback(C.GoString(url)) }
