package main

import (
	"bytes"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
)

type blockingZstdSource struct {
	startedOnce sync.Once
	closedOnce  sync.Once
	started     chan struct{}
	closed      chan struct{}
}

func newBlockingZstdSource() *blockingZstdSource {
	return &blockingZstdSource{started: make(chan struct{}), closed: make(chan struct{})}
}

func (r *blockingZstdSource) Read([]byte) (int, error) {
	r.startedOnce.Do(func() { close(r.started) })
	<-r.closed
	return 0, io.ErrClosedPipe
}

func (r *blockingZstdSource) Close() error {
	r.closedOnce.Do(func() { close(r.closed) })
	return nil
}

func encodeZstdForTest(t *testing.T, payload []byte) []byte {
	t.Helper()
	encoder, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatalf("create zstd encoder: %v", err)
	}
	defer encoder.Close()
	return encoder.EncodeAll(payload, nil)
}

func TestDecompressZstdKeepsActiveDecodersIsolated(t *testing.T) {
	zstdReaderPool = sync.Pool{
		New: func() any {
			decoder, err := zstd.NewReader(nil)
			if err != nil {
				panic(err)
			}
			return decoder
		},
	}

	firstPayload := bytes.Repeat([]byte("first response payload "), 64)
	secondPayload := bytes.Repeat([]byte("second response payload "), 64)

	first, err := decompressZstd(io.NopCloser(bytes.NewReader(encodeZstdForTest(t, firstPayload))))
	if err != nil {
		t.Fatalf("create first decoder: %v", err)
	}
	defer first.Close()

	second, err := decompressZstd(io.NopCloser(bytes.NewReader(encodeZstdForTest(t, secondPayload))))
	if err != nil {
		t.Fatalf("create second decoder: %v", err)
	}
	defer second.Close()

	firstDecoded, err := io.ReadAll(first)
	if err != nil {
		t.Fatalf("read first response: %v", err)
	}
	secondDecoded, err := io.ReadAll(second)
	if err != nil {
		t.Fatalf("read second response: %v", err)
	}

	if !bytes.Equal(firstDecoded, firstPayload) {
		t.Fatalf("first response was corrupted: got %q", firstDecoded)
	}
	if !bytes.Equal(secondDecoded, secondPayload) {
		t.Fatalf("second response was corrupted: got %q", secondDecoded)
	}
}

func TestZstdReaderCloseUnblocksPendingSourceRead(t *testing.T) {
	zstdReaderPool = sync.Pool{
		New: func() any {
			decoder, err := zstd.NewReader(nil)
			if err != nil {
				panic(err)
			}
			return decoder
		},
	}

	source := newBlockingZstdSource()
	reader, err := decompressZstd(source)
	if err != nil {
		t.Fatalf("create decoder: %v", err)
	}

	select {
	case <-source.started:
	case <-time.After(time.Second):
		t.Fatal("decoder did not start reading from the source")
	}

	closed := make(chan error, 1)
	go func() { closed <- reader.Close() }()

	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("close decoder: %v", err)
		}
	case <-time.After(time.Second):
		_ = source.Close()
		t.Fatal("closing the decoder blocked before closing its source")
	}
}
