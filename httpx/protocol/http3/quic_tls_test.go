package http3

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/dnsoa/net/httpx/core"
)

func TestQUICCryptoFrameRoundTrip(t *testing.T) {
	encoded, err := AppendQUICCryptoFrame(nil, 5, []byte("hello"))
	if err != nil {
		t.Fatalf("append crypto frame: %v", err)
	}
	frames, err := ParseQUICCryptoFrames(encoded)
	if err != nil {
		t.Fatalf("parse crypto frames: %v", err)
	}
	if len(frames) != 1 {
		t.Fatalf("expected 1 crypto frame, got %d", len(frames))
	}
	if frames[0].Offset != 5 {
		t.Fatalf("unexpected crypto offset %d", frames[0].Offset)
	}
	if string(frames[0].Data) != "hello" {
		t.Fatalf("unexpected crypto payload %q", frames[0].Data)
	}
}

func TestQUICTLSServerClientHandshakeRoundTrip(t *testing.T) {
	serverTLSConfig := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{generateQUICTLSTestCertificate(t)},
		NextProtos:   []string{"http/1.1"},
		ServerName:   "example.com",
	}
	clientTLSConfig := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{"http/1.1"},
		ServerName:         "example.com",
		InsecureSkipVerify: true,
	}

	serverHandshake, err := NewQUICTLSServerHandshake(serverTLSConfig, []byte("server-transport-params"))
	if err != nil {
		t.Fatalf("new server quic tls handshake: %v", err)
	}
	clientHandshake, err := NewQUICTLSClientHandshake(clientTLSConfig, []byte("client-transport-params"))
	if err != nil {
		t.Fatalf("new client quic tls handshake: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := serverHandshake.Start(ctx); err != nil {
		t.Fatalf("start server handshake: %v", err)
	}
	if err := clientHandshake.Start(ctx); err != nil {
		t.Fatalf("start client handshake: %v", err)
	}

	levels := []tls.QUICEncryptionLevel{
		tls.QUICEncryptionLevelInitial,
		tls.QUICEncryptionLevelHandshake,
		tls.QUICEncryptionLevelApplication,
	}
	for step := 0; step < 128; step++ {
		progress := false
		for _, level := range levels {
			clientFrames, err := clientHandshake.DrainCryptoFrames(level)
			if err != nil {
				t.Fatalf("drain client crypto frames at %s: %v", level, err)
			}
			if len(clientFrames) > 0 {
				progress = true
				if err := serverHandshake.HandleCryptoFrames(level, clientFrames); err != nil {
					t.Fatalf("server handle crypto frames at %s: %v", level, err)
				}
			}

			serverFrames, err := serverHandshake.DrainCryptoFrames(level)
			if err != nil {
				t.Fatalf("drain server crypto frames at %s: %v", level, err)
			}
			if len(serverFrames) > 0 {
				progress = true
				if err := clientHandshake.HandleCryptoFrames(level, serverFrames); err != nil {
					t.Fatalf("client handle crypto frames at %s: %v", level, err)
				}
			}
		}
		if clientHandshake.HandshakeComplete() && serverHandshake.HandshakeComplete() {
			break
		}
		if !progress {
			t.Fatalf("quic tls handshake made no progress: clientErr=%v serverErr=%v", clientHandshake.LastError(), serverHandshake.LastError())
		}
	}

	if !clientHandshake.HandshakeComplete() || !serverHandshake.HandshakeComplete() {
		t.Fatalf("expected quic tls handshake to complete: client=%v server=%v", clientHandshake.HandshakeComplete(), serverHandshake.HandshakeComplete())
	}
	if clientHandshake.ConnectionState().Version != tls.VersionTLS13 {
		t.Fatalf("unexpected client tls version %x", clientHandshake.ConnectionState().Version)
	}
	if serverHandshake.ConnectionState().Version != tls.VersionTLS13 {
		t.Fatalf("unexpected server tls version %x", serverHandshake.ConnectionState().Version)
	}
	if clientHandshake.ConnectionState().NegotiatedProtocol != HTTP3ALPN {
		t.Fatalf("unexpected client negotiated protocol %q", clientHandshake.ConnectionState().NegotiatedProtocol)
	}
	if serverHandshake.ConnectionState().NegotiatedProtocol != HTTP3ALPN {
		t.Fatalf("unexpected server negotiated protocol %q", serverHandshake.ConnectionState().NegotiatedProtocol)
	}
	if !bytes.Equal(clientHandshake.PeerTransportParameters(), []byte("server-transport-params")) {
		t.Fatalf("unexpected client peer transport params %q", clientHandshake.PeerTransportParameters())
	}
	if !bytes.Equal(serverHandshake.PeerTransportParameters(), []byte("client-transport-params")) {
		t.Fatalf("unexpected server peer transport params %q", serverHandshake.PeerTransportParameters())
	}
}

func TestServerPeerConnectionHandlesQUICTLSHandshakePackets(t *testing.T) {
	serverTLSConfig := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{generateQUICTLSTestCertificate(t)},
		NextProtos:   []string{"http/1.1"},
		ServerName:   "example.com",
	}
	clientTLSConfig := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{"http/1.1"},
		ServerName:         "example.com",
		InsecureSkipVerify: true,
	}
	streams := NewMemoryStreamOpenerFactory().NewStreamOpener()
	serverPeer, err := NewServerPeerConnection(NewServerSession(), streams)
	if err != nil {
		t.Fatalf("new server peer connection: %v", err)
	}
	if err := serverPeer.EnableTLSServer(serverTLSConfig, []byte("server-transport-params")); err != nil {
		t.Fatalf("enable server quic tls: %v", err)
	}
	clientHandshake, err := NewQUICTLSClientHandshake(clientTLSConfig, []byte("client-transport-params"))
	if err != nil {
		t.Fatalf("new client quic tls handshake: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := clientHandshake.Start(ctx); err != nil {
		t.Fatalf("start client handshake: %v", err)
	}

	dcid := bytes.Repeat([]byte{0xaa}, DefaultShortHeaderDestinationConnectionIDLength)
	scid := bytes.Repeat([]byte{0xbb}, DefaultShortHeaderDestinationConnectionIDLength)
	handler := ServerRequestHandlerFunc(func(context.Context, *core.Request) (*core.Response, error) {
		t.Fatalf("unexpected request handling during tls handshake")
		return nil, nil
	})
	levels := []tls.QUICEncryptionLevel{
		tls.QUICEncryptionLevelInitial,
		tls.QUICEncryptionLevelHandshake,
		tls.QUICEncryptionLevelApplication,
	}
	sawInitialPacket := false
	sawHandshakePacket := false

	for step := 0; step < 128; step++ {
		progress := false
		for _, level := range levels {
			clientFrames, err := clientHandshake.DrainCryptoFrames(level)
			if err != nil {
				t.Fatalf("drain client crypto frames at %s: %v", level, err)
			}
			if len(clientFrames) > 0 {
				progress = true
				var packet []byte
				switch level {
				case tls.QUICEncryptionLevelInitial:
					sawInitialPacket = true
					packet = buildTestQUICInitialPacket(t, dcid, scid, clientFrames)
				case tls.QUICEncryptionLevelHandshake:
					sawHandshakePacket = true
					packet = buildTestQUICHandshakePacket(t, dcid, scid, clientFrames)
				case tls.QUICEncryptionLevelApplication:
					packet = buildTestQUIC1RTTPacket(dcid, clientFrames)
				default:
					t.Fatalf("unexpected encryption level %s", level)
				}
				if _, err := serverPeer.HandlePacket(ctx, packet, handler); err != nil {
					t.Fatalf("server peer handle packet at %s: %v", level, err)
				}
			}

			serverFrames, err := serverPeer.DrainTLSCryptoFrames(level)
			if err != nil {
				t.Fatalf("drain server crypto frames at %s: %v", level, err)
			}
			if len(serverFrames) > 0 {
				progress = true
				if err := clientHandshake.HandleCryptoFrames(level, serverFrames); err != nil {
					t.Fatalf("client handle server crypto frames at %s: %v", level, err)
				}
			}
		}
		if clientHandshake.HandshakeComplete() && serverPeer.TLSHandshakeComplete() {
			break
		}
		if !progress {
			t.Fatalf("server peer quic tls handshake made no progress: clientErr=%v serverErr=%v", clientHandshake.LastError(), serverPeer.tlsServer.LastError())
		}
	}

	if !sawInitialPacket || !sawHandshakePacket {
		t.Fatalf("expected handshake to exercise initial and handshake packet paths: initial=%v handshake=%v", sawInitialPacket, sawHandshakePacket)
	}
	if !clientHandshake.HandshakeComplete() || !serverPeer.TLSHandshakeComplete() {
		t.Fatalf("expected server peer quic tls handshake to complete: client=%v server=%v", clientHandshake.HandshakeComplete(), serverPeer.TLSHandshakeComplete())
	}
	if serverPeer.TLSConnectionState().Version != tls.VersionTLS13 {
		t.Fatalf("unexpected server tls version %x", serverPeer.TLSConnectionState().Version)
	}
	if serverPeer.TLSConnectionState().NegotiatedProtocol != HTTP3ALPN {
		t.Fatalf("unexpected server negotiated protocol %q", serverPeer.TLSConnectionState().NegotiatedProtocol)
	}
	if clientHandshake.ConnectionState().NegotiatedProtocol != HTTP3ALPN {
		t.Fatalf("unexpected client negotiated protocol %q", clientHandshake.ConnectionState().NegotiatedProtocol)
	}
	if !bytes.Equal(serverPeer.TLSPeerTransportParameters(), []byte("client-transport-params")) {
		t.Fatalf("unexpected server peer transport params %q", serverPeer.TLSPeerTransportParameters())
	}
	snapshot := serverPeer.Snapshot()
	if snapshot.InitialPackets == 0 || snapshot.HandshakePackets == 0 {
		t.Fatalf("expected packet accounting for tls handshake, got initial=%d handshake=%d 1rtt=%d", snapshot.InitialPackets, snapshot.HandshakePackets, snapshot.OneRTTPackets)
	}
	if snapshot.InitialPacketSpace.ReceivedPackets == 0 || snapshot.HandshakePacketSpace.ReceivedPackets == 0 {
		t.Fatalf("expected packet number spaces to track tls packets, got initial=%+v handshake=%+v", snapshot.InitialPacketSpace, snapshot.HandshakePacketSpace)
	}
}

func generateQUICTLSTestCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		DNSNames:     []string{"example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create test certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
