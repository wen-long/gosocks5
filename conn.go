package gosocks5

import (
	"io"
	//"log"

	"net"
	"sync"
	"time"
)

type Selector interface {
	// return supported methods
	Methods() []uint8
	// select method
	Select(methods ...uint8) (method uint8)
	// on method selected
	OnSelected(method uint8, conn net.Conn) (net.Conn, error)
	IsAuthenticationToRead() bool
	SetAuthenticationRead()
}

type Conn struct {
	c                      net.Conn
	selector               Selector
	method                 uint8
	isClient               bool
	handshaked             bool
	handshakeMutex         sync.Mutex
	handshakeErr           error
	ShouldWaitSocks5METHOD bool
	ShouldWaitAddrResp     bool
	readMutex              sync.Mutex
}

func ClientConn(conn net.Conn, selector Selector) *Conn {
	return &Conn{
		c:        conn,
		selector: selector,
		isClient: true,
	}
}

func ServerConn(conn net.Conn, selector Selector) *Conn {
	return &Conn{
		c:        conn,
		selector: selector,
	}
}

func (conn *Conn) Handleshake(read bool) error {
	if read {
		conn.readMutex.Lock()
		defer conn.readMutex.Unlock()
	} else {
		conn.handshakeMutex.Lock()
		defer conn.handshakeMutex.Unlock()
	}

	if err := conn.handshakeErr; err != nil {
		return err
	}

	if read && conn.ShouldWaitSocks5METHOD {
		if err := conn.clientReadHandshake(); err != nil {
			conn.selector.SetAuthenticationRead()
			return err
		}
		conn.selector.SetAuthenticationRead()
		conn.ShouldWaitSocks5METHOD = false
	}

	if read && conn.ShouldWaitAddrResp {
		_, err := ReadReply(conn.c)
		if err != nil {
			return err
		}
		conn.ShouldWaitAddrResp = false
	}
	if conn.handshaked {
		return nil
	}

	if conn.isClient {
		conn.handshakeErr = conn.clientHandshake()
	} else {
		conn.handshakeErr = conn.serverHandshake()
	}

	return conn.handshakeErr
}

func (conn *Conn) clientHandshake() error {
	var methods []uint8
	var nm int

	if conn.selector != nil {
		methods = conn.selector.Methods()
	}
	nm = len(methods)
	if nm == 0 {
		nm = 1
	}

	b := make([]byte, 2+nm)
	b[0] = Ver5
	b[1] = uint8(nm)
	copy(b[2:], methods)

	if _, err := conn.c.Write(b); err != nil {
		return err
	}

	conn.ShouldWaitSocks5METHOD = true

	if conn.selector != nil {
		c, err := conn.selector.OnSelected(0, conn.c)
		if err != nil {
			return err
		}
		conn.c = c
	}
	//conn.method = b[1]
	//log.Println("method:", conn.method)
	conn.handshaked = true
	return nil
}

func (conn *Conn) clientReadHandshake() error {
	b := make([]byte, 2)
	if _, err := io.ReadFull(conn.c, b[:2]); err != nil {
		return err
	}

	if b[0] != Ver5 {
		return ErrBadVersion
	}
	if conn.selector.IsAuthenticationToRead() {
		resp, err := ReadUserPassResponse(conn.c)
		if err != nil {
			return err
		}
		if resp.Status != Succeeded {
			return ErrAuthFailure
		}
	}
	return nil
}

func (conn *Conn) serverHandshake() error {
	methods, err := ReadMethods(conn.c)
	if err != nil {
		return err
	}

	method := MethodNoAuth
	if conn.selector != nil {
		method = conn.selector.Select(methods...)
	}

	if _, err := conn.c.Write([]byte{Ver5, method}); err != nil {
		return err
	}

	if conn.selector != nil {
		c, err := conn.selector.OnSelected(method, conn.c)
		if err != nil {
			return err
		}
		conn.c = c
	}
	conn.method = method
	//log.Println("method:", method)
	conn.handshaked = true
	return nil
}

func (conn *Conn) Read(b []byte) (n int, err error) {
	if err = conn.Handleshake(true); err != nil {
		return
	}
	return conn.c.Read(b)
}

func (conn *Conn) Write(b []byte) (n int, err error) {
	if err = conn.Handleshake(false); err != nil {
		return
	}
	return conn.c.Write(b)
}

func (conn *Conn) Close() error {
	return conn.c.Close()
}

func (conn *Conn) LocalAddr() net.Addr {
	return conn.c.LocalAddr()
}

func (conn *Conn) RemoteAddr() net.Addr {
	return conn.c.RemoteAddr()
}

func (conn *Conn) SetDeadline(t time.Time) error {
	return conn.c.SetDeadline(t)
}

func (conn *Conn) SetReadDeadline(t time.Time) error {
	return conn.c.SetReadDeadline(t)
}

func (conn *Conn) SetWriteDeadline(t time.Time) error {
	return conn.c.SetWriteDeadline(t)
}
