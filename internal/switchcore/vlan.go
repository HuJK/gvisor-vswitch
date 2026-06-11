package switchcore

import "encoding/binary"

const (
	etherTypeVLAN = 0x8100

	ethHeaderLen = 14
	macLen       = 6

	// untaggedKey is the internal VLAN key for the untagged domain.
	// Tagged frames use their VID (1-4094) as key; VID 0 on the wire is a
	// priority tag (802.1Q: "no VLAN") and is folded into the untagged
	// domain.
	untaggedKey = int32(0)
)

// frameView is a parsed ethernet frame. data always starts at the
// destination MAC.
type frameView struct {
	data   []byte
	tagged bool
	vid    uint16
}

func parseFrame(data []byte) (frameView, bool) {
	if len(data) < ethHeaderLen {
		return frameView{}, false
	}
	f := frameView{data: data}
	if binary.BigEndian.Uint16(data[12:14]) == etherTypeVLAN {
		if len(data) < ethHeaderLen+4 {
			return frameView{}, false
		}
		f.tagged = true
		f.vid = binary.BigEndian.Uint16(data[14:16]) & 0x0fff
	}
	return f, true
}

func (f frameView) dstMAC() [macLen]byte {
	var m [macLen]byte
	copy(m[:], f.data[0:macLen])
	return m
}

func (f frameView) srcMAC() [macLen]byte {
	var m [macLen]byte
	copy(m[:], f.data[macLen:2*macLen])
	return m
}

func isMulticast(mac [macLen]byte) bool {
	return mac[0]&0x01 != 0
}

// ingressKey classifies an ingress frame per the port's VLAN attribute,
// returning the internal VLAN key, or ok=false if the frame must be dropped.
func ingressKey(attrs PortAttrs, f frameView) (int32, bool) {
	switch attrs.VLAN {
	case VLANTrunk:
		if f.tagged {
			// A VID-0 tag is priority-only: untagged domain.
			return int32(f.vid), true
		}
		return untaggedKey, true
	case VLANUntaggedOnly:
		if f.tagged {
			return 0, false
		}
		return untaggedKey, true
	default: // access 1-4094
		if f.tagged {
			return 0, false
		}
		return int32(attrs.VLAN), true
	}
}

// egressEligible reports whether a frame on the given VLAN key may leave
// through a port with dstAttrs, coming from a port with srcAttrs.
func egressEligible(srcAttrs, dstAttrs PortAttrs, key int32) bool {
	if dstAttrs.Disabled {
		return false
	}
	if srcAttrs.Isolated && dstAttrs.Isolated {
		return false
	}
	switch dstAttrs.VLAN {
	case VLANTrunk:
		return true
	case VLANUntaggedOnly:
		return key == untaggedKey
	default:
		return key == int32(dstAttrs.VLAN)
	}
}

// frameVariants lazily builds the tagged/untagged renderings of one frame so
// flooding to N ports does at most two allocations.
type frameVariants struct {
	f   frameView
	key int32

	untagged []byte
	tagged   []byte
}

func (v *frameVariants) untaggedForm() []byte {
	if !v.f.tagged {
		return v.f.data
	}
	if v.untagged == nil {
		d := v.f.data
		out := make([]byte, len(d)-4)
		copy(out, d[:12])
		copy(out[12:], d[16:])
		v.untagged = out
	}
	return v.untagged
}

func (v *frameVariants) taggedForm() []byte {
	if v.f.tagged {
		return v.f.data
	}
	if v.tagged == nil {
		d := v.f.data
		out := make([]byte, len(d)+4)
		copy(out, d[:12])
		binary.BigEndian.PutUint16(out[12:14], etherTypeVLAN)
		binary.BigEndian.PutUint16(out[14:16], uint16(v.key)&0x0fff)
		copy(out[16:], d[12:])
		v.tagged = out
	}
	return v.tagged
}

// egressFrame renders the frame as the destination port must see it.
func (v *frameVariants) egressFrame(dstAttrs PortAttrs) []byte {
	if dstAttrs.VLAN == VLANTrunk && v.key != untaggedKey {
		return v.taggedForm()
	}
	return v.untaggedForm()
}
