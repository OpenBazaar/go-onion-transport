package torOnion

import (
	"net"
	"path/filepath"
	"sync"
	"testing"

	ma "github.com/jbenet/go-multiaddr"
)

// NewMortalService creates a new MortalService
func NewMortalService(network, address string, connectionCallback func(net.Conn) error) *MortalService {
	l := MortalService{
		network:            network,
		address:            address,
		connectionCallback: connectionCallback,

		conns:     make([]net.Conn, 0, 10),
		stopping:  false,
		waitGroup: &sync.WaitGroup{},
	}
	return &l
}

// Start the MortalService
func (l *MortalService) Start() error {
	var err error
	log.Printf("starting listener service %s:%s", l.network, l.address)
	if l.network == "unix" {
		log.Printf("removing unix socket file %s", l.address)
		os.Remove(l.address)
	}
	l.listener, err = net.Listen(l.network, l.address)
	if err != nil {
		return err
	}
	l.waitGroup.Add(1)
	go l.acceptLoop()
	return nil
}

// Stop will kill our listener and all it's connections
func (l *MortalService) Stop() {
	log.Printf("stopping listener service %s:%s", l.network, l.address)
	l.stopping = true
	if l.listener != nil {
		l.listener.Close()
	}
	l.waitGroup.Wait()
	if l.network == "unix" {
		log.Printf("removing unix socket file %s", l.address)
		os.Remove(l.address)
	}
}

func (l *MortalService) acceptLoop() {
	defer l.waitGroup.Done()
	defer func() {
		log.Printf("acceptLoop stopping for listener service %s:%s", l.network, l.address)
		for i, conn := range l.conns {
			if conn != nil {
				log.Printf("Closing connection #%d", i)
				conn.Close()
			}
		}
	}()
	defer l.listener.Close()

	for {
		conn, err := l.listener.Accept()
		if err != nil {
			log.Printf("MortalService connection accept failure: %s\n", err)
			if l.stopping {
				return
			} else {
				continue
			}
		}

		l.conns = append(l.conns, conn)
		go l.handleConnection(conn, len(l.conns)-1)
	}
}

func (l *MortalService) handleConnection(conn net.Conn, id int) error {
	defer func() {
		log.Printf("Closing connection #%d", id)
		conn.Close()
		l.conns[id] = nil
	}()

	log.Printf("Starting connection #%d", id)
	if err := l.connectionCallback(conn); err != nil {
		// log.Println(err.Error())
		return err
	}
	return nil
}

func NewAccumulatingListener(net, address string) *AccumulatingListener {
	l := AccumulatingListener{
		net:             net,
		address:         address,
		hasProtocolInfo: true,
		hasAuthenticate: true,
	}
	return &l
}

func (a *AccumulatingListener) Start() {
	a.mortalService = service.NewMortalService(a.net, a.address, a.SessionWorker)
	err := a.mortalService.Start()
	if err != nil {
		panic(err)
	}
}

func (a *AccumulatingListener) Stop() {
	fmt.Println("AccumulatingListener STOP")
	a.mortalService.Stop()
}

func (a *AccumulatingListener) SessionWorker(conn net.Conn) error {
	connReader := bufio.NewReader(conn)
	for {

		line, err := connReader.ReadBytes('\n')
		if err != nil {
			//fmt.Println("AccumulatingListener read error:", err)
		}
		lineStr := strings.TrimSpace(string(line))
		a.buffer.WriteString(lineStr + "\n")

		if string(lineStr) == "PROTOCOLINFO" {
			if a.hasProtocolInfo {
				conn.Write([]byte(`250-PROTOCOLINFO 1
250-AUTH METHODS=NULL
250-VERSION Tor="0.2.7.6"
250 OK` + "\n"))
			} else {
				conn.Write([]byte("510 PROTOCOLINFO denied.\r\n"))
			}
		} else if string(lineStr) == "AUTHENTICATE" {
			if a.hasAuthenticate {
				conn.Write([]byte("250 OK\r\n"))
			} else {
				conn.Write([]byte("510 PROTOCOLINFO denied.\r\n"))
			}
		} else {
			conn.Write([]byte("250 OK\r\n"))
		}
	}
	return nil
}

func TestOnionTransport(t *testing.T) {
	keysDir, err := ioutil.TempDir("", "keys")
	onionKeyPath := filepath.Join(keysDir, "timaq4ygg2iegci7")
	onionKey := strings.Repeat("A", 825)
	if err := ioutil.WriteFile(onionKeyPath, onionKey, 0666); err != nil {
		t.Fail(err)
	}

	auth := proxy.Auth{
		User:     "",
		Password: "",
	}

	controlNet := "tcp"
	controlAddr := "127.0.0.1:2451"
	listener := NewAccumulatingListener(controlNet, controlAddr)
	t := NewOnionTransport(controlNet, controlAddr, &auth, keysDir)

	multiAddr, err := NewMultiaddr("/onion/timaq4ygg2iegci7:80")
	if err != nil {
		t.Fail(err)
	}
	_ := t.Listen(multiAddr)
	fmt.Println("accumulated tor control port data", t.buffer.String())
}
