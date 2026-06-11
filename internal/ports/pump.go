package ports

import (
	"sync"

	"github.com/HuJK/gvisor-vswitch/internal/switchcore"
)

const txQueueLen = 512

// pump moves frames between one frameIO and the switch under a fixed port
// ID: a reader goroutine delivers ingress frames, a writer goroutine drains
// the TX queue. When either side fails the pump stops, closes the transport
// and fires onExit exactly once.
type pump struct {
	ref *switchcore.PortRef
	io  frameIO

	txq    chan []byte
	done   chan struct{}
	once   sync.Once
	onExit func()
}

func newPump(ref *switchcore.PortRef, io frameIO, onExit func()) *pump {
	return &pump{
		ref: ref,
		io:  io,
		txq:    make(chan []byte, txQueueLen),
		done:   make(chan struct{}),
		onExit: onExit,
	}
}

func (p *pump) start() {
	go p.rxLoop()
	go p.txLoop()
}

func (p *pump) rxLoop() {
	for {
		frame, err := p.io.ReadFrame()
		if err != nil {
			p.stop()
			return
		}
		p.ref.Deliver(frame)
	}
}

func (p *pump) txLoop() {
	for {
		select {
		case frame := <-p.txq:
			if err := p.io.WriteFrame(frame); err != nil {
				p.stop()
				return
			}
		case <-p.done:
			return
		}
	}
}

// send enqueues a frame for transmission, dropping it if the queue is full
// or the pump has stopped.
func (p *pump) send(frame []byte) bool {
	select {
	case <-p.done:
		return false
	default:
	}
	select {
	case p.txq <- frame:
		return true
	default:
		return false
	}
}

func (p *pump) stop() {
	p.once.Do(func() {
		close(p.done)
		p.io.Close()
		if p.onExit != nil {
			go p.onExit()
		}
	})
}

func (p *pump) stopped() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}
