package main

/*
#include "ebpf/write_tracer.h"
*/
import "C"

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux write_tracer ./ebpf/write_tracer.c

type Event struct {
	Len      uint64
	ChunkLen uint64
	PID      uint32

	Content [C.MAX_CHUNK_SIZE]byte
	Comm    [C.TASK_COMM_LEN]byte
}

type Entry struct {
	Len        uint64
	CurrentLen uint64
	Txt        []byte
}

func main() {
	buffer := make(map[uint32]Entry)

	// Allow the current process to lock memory for eBPF programs.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock rlimit: %v", err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := write_tracerObjects{}
	if err := loadWrite_tracerObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close() // Ensure objects are closed when main exits
	pid := uint32(os.Getpid())
	objs.write_tracerVariables.FilterPid.Set(&pid)

	// Attach tracepoints (same as before)
	tp, err := link.Tracepoint("syscalls", "sys_enter_write", objs.TraceWrite, nil)
	if err != nil {
		log.Fatalf("Failed to attach tracepoint/syscalls/sys_enter_write: %v", err)
	}
	defer tp.Close()
	log.Println("eBPF programs attached to write() syscall tracepoints.")

	// Ring buffer reader for events map
	reader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("Failed to create ring buffer reader for events: %v", err)
	}
	defer reader.Close()

	go func() {
		for {
			record, err := reader.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				log.Printf("Error reading ring buffer event: %v", err)
				continue
			}

			var ev Event
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.NativeEndian, &ev); err != nil {
				log.Printf("Failed to parse event: %v", err)
				continue
			}

			entry, ok := buffer[ev.PID]
			if !ok {
				entry = Entry{Len: ev.Len}
			}
			entry.Txt = append(entry.Txt, ev.Content[:ev.ChunkLen]...)
			entry.CurrentLen += ev.ChunkLen
			buffer[ev.PID] = entry

			if entry.Len == entry.CurrentLen {
				log.Println(ev.PID, "|", string(ev.Comm[:]), "|", string(entry.Txt))
				delete(buffer, ev.PID)
			}
		}
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
}
