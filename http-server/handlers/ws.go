package handlers

import (
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	// Only accept connections from the same host (prevents cross-site WebSocket hijacking).
	// Non-browser clients (curl, custom tools) send no Origin header and are always allowed.
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		if origin == "" {
			return true
		}
		// Strip scheme from origin and compare to the server host
		stripped := strings.TrimPrefix(strings.TrimPrefix(origin, "https://"), "http://")
		return stripped == r.Host
	},
	ReadBufferSize:  1024,
	WriteBufferSize: 4096,
}

// Hub maintains the set of active WebSocket clients and broadcasts messages.
type Hub struct {
	mu        sync.Mutex
	clients   map[*wsClient]struct{}
	broadcast chan []byte
}

type wsClient struct {
	hub  *Hub
	conn *websocket.Conn
	send chan []byte
}

// NewHub creates a Hub and starts its internal goroutine.
func NewHub() *Hub {
	h := &Hub{
		clients:   make(map[*wsClient]struct{}),
		broadcast: make(chan []byte, 256),
	}
	go h.run()
	return h
}

func (h *Hub) run() {
	for msg := range h.broadcast {
		h.mu.Lock()
		for c := range h.clients {
			select {
			case c.send <- msg:
			default:
				// Slow client — close and remove
				close(c.send)
				delete(h.clients, c)
			}
		}
		h.mu.Unlock()
	}
}

// Broadcast queues a message to all connected WebSocket clients.
func (h *Hub) Broadcast(msg []byte) {
	select {
	case h.broadcast <- msg:
	default:
		log.Println("[WS] broadcast channel full — dropping message")
	}
}

// ServeWS upgrades the HTTP connection and starts pumping messages.
// If the client sent Sec-WebSocket-Protocol (browser WS auth workaround), echoes it back
// so the browser doesn't close the connection after the upgrade.
func (h *Hub) ServeWS(w http.ResponseWriter, r *http.Request) {
	var respHeader http.Header
	if prots := websocket.Subprotocols(r); len(prots) > 0 {
		respHeader = http.Header{"Sec-WebSocket-Protocol": []string{prots[0]}}
	}
	conn, err := upgrader.Upgrade(w, r, respHeader)
	if err != nil {
		log.Printf("[WS] Upgrade error: %v", err)
		return
	}

	c := &wsClient{hub: h, conn: conn, send: make(chan []byte, 64)}
	h.mu.Lock()
	h.clients[c] = struct{}{}
	h.mu.Unlock()

	go c.writePump()
	go c.readPump()
}

func (c *wsClient) writePump() {
	ticker := time.NewTicker(30 * time.Second)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()
	for {
		select {
		case msg, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			if err := c.conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				return
			}
		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

func (c *wsClient) readPump() {
	defer func() {
		c.hub.mu.Lock()
		delete(c.hub.clients, c)
		c.hub.mu.Unlock()
		c.conn.Close()
	}()
	c.conn.SetReadLimit(512)
	c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})
	for {
		if _, _, err := c.conn.ReadMessage(); err != nil {
			break
		}
	}
}
