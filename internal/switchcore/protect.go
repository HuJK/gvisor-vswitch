package switchcore

import (
	"crypto/rand"
	"encoding/binary"
	"sync/atomic"
	"time"
)

// Loop-prevention building blocks that work without full STP:
//
//   - 802.1D reserved group addresses (01:80:C2:00:00:00..0F) are never
//     forwarded (bridges must consume them); BPDUs go to the STP machinery
//     or trip the BPDU guard.
//   - Storm control bounds flooded ingress per port.
//   - Loop probes detect a port hearing the switch's own probe frames and
//     block it.

// isReservedGroupMAC reports whether dst is in 01:80:C2:00:00:00..0F.
func isReservedGroupMAC(m [macLen]byte) bool {
	return m[0] == 0x01 && m[1] == 0x80 && m[2] == 0xc2 &&
		m[3] == 0x00 && m[4] == 0x00 && m[5]&0xf0 == 0x00
}

// isBPDU reports whether the frame is an 802.1D BPDU: dst
// 01:80:C2:00:00:00, 802.3 length field, LLC DSAP/SSAP 0x42/0x42 UI.
func isBPDU(dst [macLen]byte, frame []byte) bool {
	if dst != [macLen]byte{0x01, 0x80, 0xc2, 0x00, 0x00, 0x00} {
		return false
	}
	if len(frame) < ethHeaderLen+3 {
		return false
	}
	if binary.BigEndian.Uint16(frame[12:14]) > 1500 {
		return false // not 802.3 length-encoded
	}
	return frame[14] == 0x42 && frame[15] == 0x42 && frame[16] == 0x03
}

// blockPort administratively disables a port with a reason (BPDU guard,
// loop detection, ...). Cleared by PATCH enabled=true.
func (s *Switch) blockPort(e *portEntry, reason string) {
	s.mu.Lock()
	if !e.attrs.Disabled {
		e.attrs.Disabled = true
		e.blockReason = reason
	}
	s.mu.Unlock()
	s.fdb.flushPort(e.id)
}

// BlockReason returns why a port was auto-disabled ("" if it wasn't).
func (s *Switch) BlockReason(id string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if e, ok := s.ports[id]; ok {
		return e.blockReason
	}
	return ""
}

// --- storm control ---

// stormBucket is a token bucket sized at one second's budget. It uses
// atomics so concurrent deliveries on one port stay race-free.
type stormBucket struct {
	tokens   atomic.Int64
	lastNano atomic.Int64
}

// allow refills by elapsed time and consumes one token; pps is the
// configured limit.
func (b *stormBucket) allow(pps uint32) bool {
	now := time.Now().UnixNano()
	last := b.lastNano.Load()
	if last == 0 {
		b.lastNano.Store(now)
		b.tokens.Store(int64(pps))
		last = now
	}
	if elapsed := now - last; elapsed > 0 && b.lastNano.CompareAndSwap(last, now) {
		refill := int64(float64(elapsed) / 1e9 * float64(pps))
		if t := b.tokens.Add(refill); t > int64(pps) {
			b.tokens.Store(int64(pps))
		}
	}
	return b.tokens.Add(-1) >= 0
}

// --- loop probe ---

const (
	// loopProbeEtherType is the IEEE local-experimental ethertype.
	loopProbeEtherType = 0x88B5
	loopProbeMagic     = 0x6776_7377 // "gvsw"

	defaultLoopProbeInterval = 2 * time.Second
)

// loopProbeDst is a locally-administered multicast that ordinary switches
// flood (unlike the 802.1D reserved range), so probes traverse external
// segments and come back if a loop exists.
var loopProbeDst = [macLen]byte{0x03, 0x67, 0x76, 0x73, 0x77, 0x00}

// buildLoopProbe builds a probe frame carrying the switch instance ID.
func buildLoopProbe(bridgeID uint64) []byte {
	f := make([]byte, 60)
	copy(f[0:6], loopProbeDst[:])
	// Source: locally administered unicast from the bridge ID.
	f[6] = 0x02
	binary.BigEndian.PutUint32(f[7:11], uint32(bridgeID>>16))
	f[11] = byte(bridgeID >> 8)
	binary.BigEndian.PutUint16(f[12:14], loopProbeEtherType)
	binary.BigEndian.PutUint32(f[14:18], loopProbeMagic)
	binary.BigEndian.PutUint64(f[18:26], bridgeID)
	return f
}

// isOwnLoopProbe reports whether the frame is a loop probe sent by this
// switch instance.
func (s *Switch) isOwnLoopProbe(frame []byte) bool {
	if len(frame) < 26 {
		return false
	}
	if binary.BigEndian.Uint16(frame[12:14]) != loopProbeEtherType {
		return false
	}
	if binary.BigEndian.Uint32(frame[14:18]) != loopProbeMagic {
		return false
	}
	return binary.BigEndian.Uint64(frame[18:26]) == s.instanceID
}

// SetLoopProbeInterval tunes how often loop probes go out (tests use small
// values).
func (s *Switch) SetLoopProbeInterval(d time.Duration) {
	if d > 0 {
		s.loopProbeNanos.Store(int64(d))
	}
}

// loopProbeLoop periodically emits probes out of loop-detect ports.
func (s *Switch) loopProbeLoop() {
	for {
		interval := time.Duration(s.loopProbeNanos.Load())
		select {
		case <-s.stop:
			return
		case <-time.After(interval):
			s.mu.RLock()
			var targets []*portEntry
			for _, e := range s.ports {
				if e.attrs.LoopDetect && !e.attrs.Disabled {
					targets = append(targets, e)
				}
			}
			s.mu.RUnlock()
			for _, e := range targets {
				e.port.Send(Meta{SrcPortID: "loop-probe"}, buildLoopProbe(s.instanceID))
			}
		}
	}
}

func newInstanceID() uint64 {
	var b [8]byte
	rand.Read(b[:])
	return binary.BigEndian.Uint64(b[:])
}
