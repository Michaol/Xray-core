package quic

import (
	"crypto"
	"crypto/aes"
	"crypto/tls"
	"encoding/binary"
	"io"

	"github.com/quic-go/quic-go/quicvarint"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	ptls "github.com/xtls/xray-core/common/protocol/tls"
	"golang.org/x/crypto/hkdf"
)

type SniffHeader struct {
	domain string
}

func (s SniffHeader) Protocol() string {
	return "quic"
}

func (s SniffHeader) Domain() string {
	return s.domain
}

const (
	versionDraft29 uint32 = 0xff00001d
	version1       uint32 = 0x1
	version2       uint32 = 0x6b3343cf // QUIC v2 (RFC 9369)
)

var (
	quicSaltOld  = []byte{0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99}
	quicSalt     = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
	quicSaltV2   = []byte{0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9}
	initialSuite = &CipherSuiteTLS13{
		ID:     tls.TLS_AES_128_GCM_SHA256,
		KeyLen: 16,
		AEAD:   AEADAESGCMTLS13,
		Hash:   crypto.SHA256,
	}
	errNotQuic        = errors.New("not quic")
	errNotQuicInitial = errors.New("not initial packet")
)

func SniffQUIC(b []byte) (*SniffHeader, error) {
	if len(b) == 0 {
		return nil, common.ErrNoClue
	}

	// Crypto data separated across packets
	cryptoLen := int32(0)
	cryptoDataBuf := buf.NewWithSize(32767)
	defer cryptoDataBuf.Release()
	cache := buf.New()
	defer cache.Release()

	// Parse QUIC packets
	for len(b) > 0 {
		buffer := buf.FromBytes(b)
		typeByte, err := buffer.ReadByte()
		if err != nil {
			return nil, errNotQuic
		}

		isLongHeader := typeByte&0x80 > 0
		if !isLongHeader || typeByte&0x40 == 0 {
			return nil, errNotQuicInitial
		}

		vb, err := buffer.ReadBytes(4)
		if err != nil {
			return nil, errNotQuic
		}

		versionNumber := binary.BigEndian.Uint32(vb)
		if versionNumber != 0 && typeByte&0x40 == 0 {
			return nil, errNotQuic
		} else if versionNumber != versionDraft29 && versionNumber != version1 && versionNumber != version2 {
			return nil, errNotQuic
		}

		packetType := (typeByte & 0x30) >> 4
		// QUIC v2 uses packet type 0x1 for Initial, v1/Draft29 uses 0x0
		isQuicInitial := (packetType == 0x0 && versionNumber != version2) || (packetType == 0x1 && versionNumber == version2)

		var destConnID []byte
		if l, err := buffer.ReadByte(); err != nil {
			return nil, errNotQuic
		} else if destConnID, err = buffer.ReadBytes(int32(l)); err != nil {
			return nil, errNotQuic
		}

		if l, err := buffer.ReadByte(); err != nil {
			return nil, errNotQuic
		} else if common.Error2(buffer.ReadBytes(int32(l))) != nil {
			return nil, errNotQuic
		}

		if isQuicInitial { // Only initial packets have token, see https://datatracker.ietf.org/doc/html/rfc9000#section-17.2.2
			tokenLen, err := quicvarint.Read(buffer)
			if err != nil || tokenLen > uint64(len(b)) {
				return nil, errNotQuic
			}

			if _, err = buffer.ReadBytes(int32(tokenLen)); err != nil {
				return nil, errNotQuic
			}
		}

		packetLen, err := quicvarint.Read(buffer)
		if err != nil {
			return nil, errNotQuic
		}
		// packetLen is impossible to be shorter than this
		if packetLen < 4 {
			return nil, errNotQuic
		}

		hdrLen := len(b) - int(buffer.Len())
		if len(b) < hdrLen+int(packetLen) {
			return nil, common.ErrNoClue // Not enough data to read as a QUIC packet. QUIC is UDP-based, so this is unlikely to happen.
		}

		restPayload := b[hdrLen+int(packetLen):]
		if !isQuicInitial { // Skip this packet if it's not initial packet
			b = restPayload
			continue
		}

		decrypted, err := decryptInitialPacket(b, buffer, versionNumber, destConnID, hdrLen, packetLen, cache)
		if err != nil {
			return nil, err
		}

		if err := parseFrames(decrypted, &cryptoLen, cryptoDataBuf); err != nil {
			return nil, err
		}

		tlsHdr := &ptls.SniffHeader{}
		err = ptls.ReadClientHello(cryptoDataBuf.BytesRange(0, cryptoLen), tlsHdr)
		if err != nil {
			// The crypto data may have not been fully recovered in current packets,
			// So we continue to sniff rest packets.
			b = restPayload
			continue
		}
		return &SniffHeader{domain: tlsHdr.Domain()}, nil
	}
	// All payload is parsed as valid QUIC packets, but we need more packets for crypto data to read client hello.
	return nil, protocol.ErrProtoNeedMoreData
}

func decryptInitialPacket(b []byte, buffer *buf.Buffer, versionNumber uint32, destConnID []byte, hdrLen int, packetLen uint64, cache *buf.Buffer) ([]byte, error) {
	var salt []byte
	switch versionNumber {
	case version2:
		salt = quicSaltV2
	case version1:
		salt = quicSalt
	default:
		salt = quicSaltOld
	}
	initialSecret := hkdf.Extract(crypto.SHA256.New, destConnID, salt)
	secret := hkdfExpandLabel(crypto.SHA256, initialSecret, []byte{}, "client in", crypto.SHA256.Size())

	var hpLabel, keyLabel, ivLabel string
	if versionNumber == version2 {
		hpLabel = "quicv2 hp"
		keyLabel = "quicv2 key"
		ivLabel = "quicv2 iv"
	} else {
		hpLabel = "quic hp"
		keyLabel = "quic key"
		ivLabel = "quic iv"
	}

	hpKey := hkdfExpandLabel(initialSuite.Hash, secret, []byte{}, hpLabel, initialSuite.KeyLen)
	block, err := aes.NewCipher(hpKey)
	if err != nil {
		return nil, err
	}

	cache.Clear()
	mask := cache.Extend(int32(block.BlockSize()))
	block.Encrypt(mask, b[hdrLen+4:hdrLen+4+len(mask)])
	b[0] ^= mask[0] & 0xf
	packetNumberLength := int(b[0]&0x3 + 1)
	for i := range packetNumberLength {
		b[hdrLen+i] ^= mask[i+1]
	}

	key := hkdfExpandLabel(crypto.SHA256, secret, []byte{}, keyLabel, 16)
	iv := hkdfExpandLabel(crypto.SHA256, secret, []byte{}, ivLabel, 12)
	cipher := AEADAESGCMTLS13(key, iv)

	nonce := cache.Extend(int32(cipher.NonceSize()))
	_, err = buffer.Read(nonce[len(nonce)-packetNumberLength:])
	if err != nil {
		return nil, err
	}

	extHdrLen := hdrLen + packetNumberLength
	data := b[extHdrLen : int(packetLen)+hdrLen]
	decrypted, err := cipher.Open(b[extHdrLen:extHdrLen], nonce, data, b[:extHdrLen])
	if err != nil {
		return nil, err
	}
	return decrypted, nil
}

func parseFrames(decrypted []byte, cryptoLen *int32, cryptoDataBuf *buf.Buffer) error {
	buffer := buf.FromBytes(decrypted)
	for !buffer.IsEmpty() {
		frameType, _ := buffer.ReadByte()
		for frameType == 0x0 && !buffer.IsEmpty() {
			frameType, _ = buffer.ReadByte()
		}
		switch frameType {
		case 0x00: // PADDING frame
		case 0x01: // PING frame
		case 0x02, 0x03: // ACK frame
			if _, err := quicvarint.Read(buffer); err != nil { // Field: Largest Acknowledged
				return io.ErrUnexpectedEOF
			}
			if _, err := quicvarint.Read(buffer); err != nil { // Field: ACK Delay
				return io.ErrUnexpectedEOF
			}
			ackRangeCount, err := quicvarint.Read(buffer) // Field: ACK Range Count
			if err != nil {
				return io.ErrUnexpectedEOF
			}
			if _, err = quicvarint.Read(buffer); err != nil { // Field: First ACK Range
				return io.ErrUnexpectedEOF
			}
			for i := 0; i < int(ackRangeCount); i++ { // Field: ACK Range
				if _, err = quicvarint.Read(buffer); err != nil { // Field: ACK Range -> Gap
					return io.ErrUnexpectedEOF
				}
				if _, err = quicvarint.Read(buffer); err != nil { // Field: ACK Range -> ACK Range Length
					return io.ErrUnexpectedEOF
				}
			}
			if frameType == 0x03 {
				if _, err = quicvarint.Read(buffer); err != nil { // Field: ECN Counts -> ECT0 Count
					return io.ErrUnexpectedEOF
				}
				if _, err = quicvarint.Read(buffer); err != nil { // Field: ECN Counts -> ECT1 Count
					return io.ErrUnexpectedEOF
				}
				if _, err = quicvarint.Read(buffer); err != nil { //nolint:misspell // Field: ECN Counts -> ECT-CE Count
					return io.ErrUnexpectedEOF
				}
			}
		case 0x06: // CRYPTO frame, we will use this frame
			offset, err := quicvarint.Read(buffer) // Field: Offset
			if err != nil {
				return io.ErrUnexpectedEOF
			}
			length, err := quicvarint.Read(buffer) // Field: Length
			if err != nil || length > uint64(buffer.Len()) {
				return io.ErrUnexpectedEOF
			}
			currentCryptoLen := int32(offset + length)
			if *cryptoLen < currentCryptoLen {
				if cryptoDataBuf.Cap() < currentCryptoLen {
					return io.ErrShortBuffer
				}
				cryptoDataBuf.Extend(currentCryptoLen - *cryptoLen)
				*cryptoLen = currentCryptoLen
			}
			if _, err := buffer.Read(cryptoDataBuf.BytesRange(int32(offset), currentCryptoLen)); err != nil { // Field: Crypto Data
				return io.ErrUnexpectedEOF
			}
		case 0x1c: // CONNECTION_CLOSE frame, only 0x1c is permitted in initial packet
			if _, err := quicvarint.Read(buffer); err != nil { // Field: Error Code
				return io.ErrUnexpectedEOF
			}
			if _, err := quicvarint.Read(buffer); err != nil { // Field: Frame Type
				return io.ErrUnexpectedEOF
			}
			length, err := quicvarint.Read(buffer) // Field: Reason Phrase Length
			if err != nil {
				return io.ErrUnexpectedEOF
			}
			if _, err := buffer.ReadBytes(int32(length)); err != nil { // Field: Reason Phrase
				return io.ErrUnexpectedEOF
			}
		default:
			// Only above frame types are permitted in initial packet.
			// See https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2.2-8
			return errNotQuicInitial
		}
	}
	return nil
}

func hkdfExpandLabel(hash crypto.Hash, secret, context []byte, label string, length int) []byte {
	b := make([]byte, 3, 3+6+len(label)+1+len(context))
	binary.BigEndian.PutUint16(b, uint16(length))
	b[2] = uint8(6 + len(label))
	b = append(b, []byte("tls13 ")...)
	b = append(b, []byte(label)...)
	b = b[:3+6+len(label)+1]
	b[3+6+len(label)] = uint8(len(context))
	b = append(b, context...)

	out := make([]byte, length)
	n, err := hkdf.Expand(hash.New, secret, b).Read(out)
	if err != nil || n != length {
		panic("quic: HKDF-Expand-Label invocation failed unexpectedly")
	}
	return out
}
