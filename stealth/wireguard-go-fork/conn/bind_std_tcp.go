/*
 * Copyright (c) 2022. Proton AG
 *
 * This file is part of ProtonVPN.
 *
 * ProtonVPN is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * ProtonVPN is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with ProtonVPN.  If not, see <https://www.gnu.org/licenses/>.
 */

package conn

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	tls "github.com/refraction-networking/utls"
	server_name_utils "golang.zx2c4.com/wireguard/conn/server_name_utils"
)

var lastErrorTimestamp time.Time

const (
	tcpWriteTimeout = 5 * time.Second
	// Stall threshold: above RekeyTimeout+KeepaliveTimeout so ordinary
	// handshake retries are not mistaken for a stall, far below
	// RejectAfterTime (180s) so session keys survive a reset.
	tcpStallAfter = 15 * time.Second
)

var nextHelloIdx atomic.Int32
var hellos = []tls.ClientHelloID{
	tls.HelloChrome_Auto,
	tls.HelloChrome_120_PQ,
	tls.HelloChrome_115_PQ,
	tls.HelloChrome_133,
}

type StdNetBindTcp struct {
	mu sync.Mutex

	useTls        bool
	tcp           *net.TCPConn
	tls           *tls.UConn
	endpoint      *StdNetEndpoint
	currentPacket *bytes.Reader
	closed        bool
	log           *Logger
	errorChan     chan<- error
	// UnixNano of the last successful readNextPacket; used to detect a
	// DPI blackhole (open conn, zero progress) and re-dial fresh.
	lastRx             atomic.Int64
	protectSocket      func(fd int) int
	serverNameStrategy server_name_utils.ServerNameStrategy

	tunsafe *TunSafeData
}

//goland:noinspection GoUnusedExportedFunction
func CreateStdNetBind(
	socketType string,
	serverNameStrategy server_name_utils.ServerNameStrategy,
	log *Logger,
	errorChan chan<- error,
	protectSocket func(fd int) int,
) Bind {
	if socketType == "udp" {
		return NewStdNetBind(protectSocket)
	} else {
		return &StdNetBindTcp{tunsafe: NewTunSafeData(), useTls: socketType == "tls", log: log,
			errorChan: errorChan, protectSocket: protectSocket, serverNameStrategy: serverNameStrategy}
	}
}

func (bind *StdNetBindTcp) ParseEndpoint(s string) (Endpoint, error) {
	e, err := netip.ParseAddrPort(s)
	if err == nil {
		bind.endpoint = (*StdNetEndpoint)(&e)
	}
	return asEndpoint(e), err
}

func dialTcp(addr string, protectSocket func(fd int) int) (*net.TCPConn, int, error) {
	protectStatus := -1
	control := func(network, address string, conn syscall.RawConn) error {
		return conn.Control(func(fd uintptr) {
			protectStatus = protectSocket(int(fd))
		})
	}

	dialer := net.Dialer{Timeout: 5 * time.Second, Control: control}
	netConn, err := dialer.Dial("tcp", addr)
	if protectStatus < 0 {
		return nil, 0, fmt.Errorf("Failed to protect socket: status=%d", protectStatus)
	}
	if err != nil {
		return nil, 0, err
	}

	conn := netConn.(*net.TCPConn)
	conn.SetLinger(0)

	// Retrieve port.
	laddr := conn.LocalAddr()
	taddr, err := net.ResolveTCPAddr(
		laddr.Network(),
		laddr.String(),
	)
	if err != nil {
		_ = conn.Close()
		return nil, 0, err
	}
	return conn, taddr.Port, nil
}

func (bind *StdNetBindTcp) upgradeToTls(addr string) error {
	serverName := server_name_utils.ServerNameFor(bind.serverNameStrategy, addr)
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         serverName,
	}

	conn := tls.UClient(bind.tcp, tlsConf, hellos[nextHelloIdx.Load()])
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	bind.log.Verbosef("TLS: Starting handshake hello=%v name=%v", nextHelloIdx.Load(), serverName)
	err := conn.Handshake()
	bind.log.Verbosef("TLS: Handshake result: %v", err)
	conn.SetDeadline(time.Time{})
	// Rotate the ClientHello on EVERY handshake (not just errors): reusing
	// the identical fingerprint on every re-dial lets DPI profile and
	// throttle repeat connections after the first grace window.
	nextHelloIdx.Store((nextHelloIdx.Load() + 1) % int32(len(hellos)))

	// On some devices (e.g. Samsung S21 FE) we see first WireGuard handshake failing on TLS socket and adding small
	// delay seems to fix that - issue is likely with timing on the server side, but couldn't find server-side fix.
	time.Sleep(100 * time.Millisecond)

	if err == nil {
		bind.tls = conn
	} else {
		newHelloIdx := (nextHelloIdx.Load() + 1) % int32(len(hellos))
		nextHelloIdx.Store(newHelloIdx) // move to next hello on error
		bind.onSocketError(err)
		conn.Close()
	}
	return err
}

func (bind *StdNetBindTcp) Open(uport uint16) ([]ReceiveFunc, uint16, error) {
	bind.mu.Lock()
	defer bind.mu.Unlock()

	bind.log.Verbosef("TCP/TLS: Open %d", uport)
	bind.closed = false
	bind.lastRx.Store(time.Now().UnixNano())
	return []ReceiveFunc{bind.makeReceiveFunc()}, uport, nil
}

func (bind *StdNetBindTcp) initTcp(addr string) error {
	var err error

	if bind.tcp != nil {
		return ErrBindAlreadyOpen
	}

	var tcp *net.TCPConn

	tcp, _, err = dialTcp(addr, bind.protectSocket)
	bind.log.Verbosef("TCP dial result: %v", err)
	if err != nil {
		bind.onSocketError(err)
		return err
	}
	bind.tcp = tcp
	return nil
}

func (bind *StdNetBindTcp) Close() error {
	bind.mu.Lock()
	defer bind.mu.Unlock()

	bind.log.Verbosef("TCP/TLS: Close")
	bind.closed = true
	err := bind.closeInternal()
	return err
}

func (bind *StdNetBindTcp) closeInternal() error {
	var err error
	if bind.tls != nil {
		err = bind.tls.Close()
		bind.tls = nil
	}
	if bind.tcp != nil {
		err = bind.tcp.Close()
		bind.tcp = nil
	}
	bind.tunsafe.clear()
	return err
}

func (bind *StdNetBindTcp) getConn() (net.Conn, error) {
	bind.mu.Lock()
	defer bind.mu.Unlock()

	if bind.closed {
		return nil, net.ErrClosed
	}

	// NB: no bind.closed=true on transient dial errors; only Close() sets
	// closed. Otherwise one failed re-dial bricks the bind (net.ErrClosed
	// forever until Open) instead of retrying on the next Send/recv.
	return bind.getConnInternal()
}

func (bind *StdNetBindTcp) getConnInternal() (net.Conn, error) {
	addr := bind.endpoint.DstToString()
	// Blackhole reset: stalled-but-open conn (no error, no rx) -> drop it
	// here under mu so both Send and recv paths re-dial fresh below.
	if (bind.tls != nil || bind.tcp != nil) && bind.stalledLocked() {
		bind.log.Errorf("TCP/TLS stalled %.0fs without rx, re-dialing %s",
			time.Since(time.Unix(0, bind.lastRx.Load())).Seconds(), addr)
		_ = bind.closeInternal()
	}
	if bind.tcp == nil {
		err := bind.initTcp(addr)
		if err != nil {
			return nil, err
		}
	}
	if !bind.useTls {
		return bind.tcp, nil
	}
	if bind.tls == nil {
		err := bind.upgradeToTls(addr)
		if err != nil {
			bind.closeInternal()
			return nil, err
		}
	}
	return bind.tls, nil
}

// resetConn closes and nils the current conn so the next getConn
// re-dials. Call only when bind.mu is NOT held (Send/recv error paths);
// getConnInternal does its own reset inline while holding mu.
func (bind *StdNetBindTcp) resetConn() {
	bind.mu.Lock()
	defer bind.mu.Unlock()
	if bind.closed {
		return
	}
	_ = bind.closeInternal()
}

// stalledLocked reports no successful rx for tcpStallAfter.
// Caller must hold bind.mu.
func (bind *StdNetBindTcp) stalledLocked() bool {
	rx := bind.lastRx.Load()
	if rx == 0 {
		return false
	}
	return time.Since(time.Unix(0, rx)) > tcpStallAfter
}

func (bind *StdNetBindTcp) makeReceiveFunc() ReceiveFunc {
	return func(buff []byte) (int, Endpoint, error) {
		var err error
		if bind.currentPacket == nil || bind.currentPacket.Len() == 0 {
			var conn net.Conn
			conn, err = bind.getConn()
			if err != nil {
				bind.logError("recv getConn", err)
				return 0, bind.endpoint, err
			}
			err = bind.readNextPacket(conn)
			if err != nil {
				if !errors.Is(err, net.ErrClosed) {
					bind.onSocketError(err)
					bind.logError("recv", err)
					bind.resetConn()
				}
				return 0, bind.endpoint, err
			}
		}
		n, err := bind.currentPacket.Read(buff)
		if err != nil {
			bind.logError("read packet", err)
			return n, bind.endpoint, err
		}
		return n, bind.endpoint, err
	}
}

func (bind *StdNetBindTcp) readNextPacket(conn net.Conn) error {
	tunSafeHeader := make([]byte, tunSafeHeaderSize)
	// Unblock a parked ReadFull so the stall reset can fire even with no
	// tx in flight; cleared below after a successful packet.
	_ = conn.SetReadDeadline(time.Now().Add(tcpStallAfter))
	_, err := io.ReadFull(conn, tunSafeHeader)
	if err != nil {
		return err
	}

	tunSafeType, payloadSize := parseTunSafeHeader(tunSafeHeader)
	wgPacket, offset, err := bind.tunsafe.prepareWgPacket(tunSafeType, payloadSize)
	if err != nil {
		return err
	}

	_, err = io.ReadFull(conn, wgPacket[offset:])
	if err != nil {
		return err
	}

	bind.tunsafe.onRecvPacket(tunSafeType, wgPacket)
	bind.currentPacket = bytes.NewReader(wgPacket)
	_ = conn.SetReadDeadline(time.Time{})
	bind.lastRx.Store(time.Now().UnixNano())
	return nil
}

func (bind *StdNetBindTcp) Send(buff []byte, endpoint Endpoint) error {
	conn, err := bind.getConn()
	if err != nil {
		bind.logError("send conn", err)
		return err
	}

	// As single tcp socket can send only to single destination. We assume endpoint passed to ParseEndpoint will be
	// the same. Compare by destination string (not interface equality):
	// after the first received packet the device stores the *pointer*
	// bind.endpoint via SetEndpointFromPacket while boundEndpoint below
	// is a value -- always unequal, which permanently rejects EVERY send
	// (handshake re-tries and data alike) with "endpoints mismatch".
	if endpoint == nil || bind.endpoint == nil ||
		endpoint.DstToString() != bind.endpoint.DstToString() {
		return errors.New("StdNetBindTcp.Send endpoints mismatch")
	}

	tunSafePacket := bind.tunsafe.wgToTunSafe(buff)
	// Unblock the single sequential sender when DPI blackholes
	// post-handshake bytes: Write fails with i/o timeout -> resetConn
	// so the next Send re-dials fresh instead of parking forever.
	_ = conn.SetWriteDeadline(time.Now().Add(tcpWriteTimeout))
	_, err = conn.Write(tunSafePacket)
	_ = conn.SetWriteDeadline(time.Time{})
	if err != nil {
		bind.onSocketError(err)
		bind.logError("send", err)
		bind.resetConn()
	}
	return err
}

func (bind *StdNetBindTcp) SetMark(_ uint32) error {
	return nil
}

func (bind *StdNetBindTcp) onSocketError(err error) {
	if err != nil && !bind.closed {
		bind.errorChan <- err
	}
}

func (bind *StdNetBindTcp) logError(t string, err error) {
	if time.Now().After(lastErrorTimestamp.Add(5 * time.Second)) {
		lastErrorTimestamp = time.Now()
		bind.log.Errorf("TCP/TLS error %s: %v", t, err)
	}
}
