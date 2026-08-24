package gw

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
)

func TestStreamMuxOpenClose(t *testing.T) {
	ca, cb := net.Pipe()
	muxA := NewStreamMux(ca)
	muxB := NewStreamMux(cb)
	defer muxA.Close()
	defer muxB.Close()

	stream, err := muxA.Open()
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}

	accepted, err := muxB.Accept()
	if err != nil {
		t.Fatalf("accept stream: %v", err)
	}

	data := []byte("hello mux")
	_, err = stream.Write(data)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	stream.Close()

	buf := make([]byte, 32)
	n, err := accepted.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(buf[:n], data) {
		t.Fatalf("expected %q, got %q", data, buf[:n])
	}
	accepted.Close()
}

func TestStreamMuxMultipleStreams(t *testing.T) {
	ca, cb := net.Pipe()
	muxA := NewStreamMux(ca)
	muxB := NewStreamMux(cb)
	defer muxA.Close()
	defer muxB.Close()

	var streams []*MuxStream
	var accepted []*MuxStream

	for i := 0; i < 5; i++ {
		s, err := muxA.Open()
		if err != nil {
			t.Fatalf("open stream %d: %v", i, err)
		}
		streams = append(streams, s)
	}

	for i := 0; i < 5; i++ {
		a, err := muxB.Accept()
		if err != nil {
			t.Fatalf("accept stream %d: %v", i, err)
		}
		accepted = append(accepted, a)
	}

	for i, s := range streams {
		msg := []byte{byte(i)}
		s.Write(msg)
		s.Close()
	}

	for i, a := range accepted {
		buf := make([]byte, 1)
		n, err := a.Read(buf)
		if err != nil {
			t.Fatalf("read stream %d: %v", i, err)
		}
		if buf[0] != byte(i) {
			t.Fatalf("stream %d: expected %d, got %d", i, i, buf[0])
		}
		_ = n
		a.Close()
	}
}

func TestStreamMuxConcurrentBidirectional(t *testing.T) {
	ca, cb := net.Pipe()
	muxA := NewStreamMux(ca)
	muxB := NewStreamMux(cb)
	defer muxA.Close()
	defer muxB.Close()

	streamA, err := muxA.Open()
	if err != nil {
		t.Fatal(err)
	}
	acceptedB, err := muxB.Accept()
	if err != nil {
		t.Fatal(err)
	}

	streamB, err := muxB.Open()
	if err != nil {
		t.Fatal(err)
	}
	acceptedA, err := muxA.Accept()
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	wg.Add(4)

	go func() {
		defer wg.Done()
		streamA.Write([]byte("fromA"))
		streamA.Close()
	}()
	go func() {
		defer wg.Done()
		buf := make([]byte, 32)
		n, _ := acceptedB.Read(buf)
		if string(buf[:n]) != "fromA" {
			t.Errorf("expected fromA, got %s", buf[:n])
		}
		acceptedB.Close()
	}()
	go func() {
		defer wg.Done()
		streamB.Write([]byte("fromB"))
		streamB.Close()
	}()
	go func() {
		defer wg.Done()
		buf := make([]byte, 32)
		n, _ := acceptedA.Read(buf)
		if string(buf[:n]) != "fromB" {
			t.Errorf("expected fromB, got %s", buf[:n])
		}
		acceptedA.Close()
	}()
	wg.Wait()
}

func TestStreamMuxCloseIdempotent(t *testing.T) {
	ca, _ := net.Pipe()
	muxA := NewStreamMux(ca)
	muxA.Close()
	muxA.Close()
}

func TestStreamMuxOpenAfterClose(t *testing.T) {
	ca, _ := net.Pipe()
	muxA := NewStreamMux(ca)
	muxA.Close()
	_, err := muxA.Open()
	if err == nil {
		t.Fatal("expected error opening stream after close")
	}
}

func TestStreamMuxLargeData(t *testing.T) {
	ca, cb := net.Pipe()
	muxA := NewStreamMux(ca)
	muxB := NewStreamMux(cb)
	defer muxA.Close()
	defer muxB.Close()

	stream, err := muxA.Open()
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := muxB.Accept()
	if err != nil {
		t.Fatal(err)
	}

	largeData := make([]byte, 100000)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		stream.Write(largeData)
		stream.Close()
	}()
	go func() {
		defer wg.Done()
		received := make([]byte, len(largeData))
		_, err := io.ReadFull(accepted, received)
		if err != nil {
			t.Errorf("read full: %v", err)
		}
		if !bytes.Equal(received, largeData) {
			t.Error("data mismatch")
		}
		accepted.Close()
	}()
	wg.Wait()
}
