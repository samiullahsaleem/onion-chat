// onion-chat is a tiny relay for end-to-end encrypted, one-to-one chat.
//
// The server keeps everything in memory and never sees plaintext: browsers
// agree on keys with ECDH and only ciphertext passes through here. There is
// no database, no request logging and nothing written to disk.
package main

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"flag"
	"io"
	"io/fs"
	"log"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

//go:embed web
var webFiles embed.FS

const (
	maxUsers     = 500
	maxBodyBytes = 24 << 10
	queueLen     = 256
	gracePeriod  = 20 * time.Second // how long a dropped connection keeps its name
	pingEvery    = 15 * time.Second // keeps Tor circuits from idling out
	sendRate     = 10.0             // relayed messages per second, per user
	sendBurst    = 40.0
	joinRate     = 5.0 // new names per second, server wide
	joinBurst    = 20.0
)

var (
	namePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{3,24}$`)
	relayTypes  = map[string]bool{"req": true, "acc": true, "dec": true, "end": true, "msg": true, "typ": true}
)

// bucket is a token-bucket rate limiter. Callers hold hub.mu.
type bucket struct {
	tokens, rate, burst float64
	last                time.Time
}

func newBucket(rate, burst float64) bucket {
	return bucket{tokens: burst, rate: rate, burst: burst, last: time.Now()}
}

func (b *bucket) allow() bool {
	now := time.Now()
	b.tokens = min(b.burst, b.tokens+now.Sub(b.last).Seconds()*b.rate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

type user struct {
	name     string
	token    string
	queue    chan []byte   // outgoing events; survives reconnects
	stream   chan struct{} // closed to evict the attached event stream; nil if none
	lastSeen time.Time
	limit    bucket
}

type hub struct {
	mu      sync.Mutex
	byName  map[string]*user // keyed by lower-cased name so "Alice" can't pose as "alice"
	byToken map[string]*user
	joins   bucket
	dirty   bool // the online list changed and needs broadcasting
}

func newHub() *hub {
	return &hub{
		byName:  map[string]*user{},
		byToken: map[string]*user{},
		joins:   newBucket(joinRate, joinBurst),
	}
}

// run reaps disconnected users and broadcasts the online list at most once a second.
func (h *hub) run() {
	for range time.Tick(time.Second) {
		h.mu.Lock()
		for _, u := range h.byName {
			if u.stream == nil && time.Since(u.lastSeen) > gracePeriod {
				h.remove(u)
			}
		}
		if h.dirty {
			h.dirty = false
			ev := h.usersEvent()
			for _, u := range h.byName {
				select {
				case u.queue <- ev:
				default:
				}
			}
		}
		h.mu.Unlock()
	}
}

// remove forgets a user. Callers hold h.mu.
func (h *hub) remove(u *user) {
	delete(h.byName, strings.ToLower(u.name))
	delete(h.byToken, u.token)
	if u.stream != nil {
		close(u.stream)
		u.stream = nil
	}
	h.dirty = true
}

// usersEvent encodes the sorted online list. Callers hold h.mu.
func (h *hub) usersEvent() []byte {
	names := make([]string, 0, len(h.byName))
	for _, u := range h.byName {
		names = append(names, u.name)
	}
	sort.Slice(names, func(i, j int) bool { return strings.ToLower(names[i]) < strings.ToLower(names[j]) })
	return frame(map[string]any{"k": "users", "users": names})
}

func (h *hub) auth(r *http.Request) *user {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.byToken[token]
}

func (h *hub) join(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if !decode(w, r, &req) {
		return
	}
	name := strings.TrimSpace(req.Name)
	if !namePattern.MatchString(name) {
		http.Error(w, "Names are 3-24 letters, digits, _ or -.", http.StatusBadRequest)
		return
	}

	h.mu.Lock()
	var status int
	var reason string
	switch {
	case !h.joins.allow():
		status, reason = http.StatusTooManyRequests, "Too many people joining right now. Try again in a moment."
	case len(h.byName) >= maxUsers:
		status, reason = http.StatusServiceUnavailable, "The server is full. Try again later."
	case h.byName[strings.ToLower(name)] != nil:
		status, reason = http.StatusConflict, "That name is taken right now."
	default:
		u := &user{
			name:     name,
			token:    newToken(),
			queue:    make(chan []byte, queueLen),
			lastSeen: time.Now(),
			limit:    newBucket(sendRate, sendBurst),
		}
		h.byName[strings.ToLower(name)] = u
		h.byToken[u.token] = u
		h.dirty = true
		reason = u.token
	}
	h.mu.Unlock()

	if status != 0 {
		http.Error(w, reason, status)
		return
	}
	writeJSON(w, map[string]string{"name": name, "token": reason})
}

// events streams a user's queue as Server-Sent Events. A newer stream for the
// same session evicts the older one, so EventSource reconnects just work.
func (h *hub) events(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	u := h.byToken[r.URL.Query().Get("t")]
	if u == nil {
		h.mu.Unlock()
		http.Error(w, "Unknown session.", http.StatusUnauthorized)
		return
	}
	if u.stream != nil {
		close(u.stream)
	}
	evict := make(chan struct{})
	u.stream = evict
	snapshot := h.usersEvent()
	h.mu.Unlock()

	defer func() {
		h.mu.Lock()
		if u.stream == evict {
			u.stream = nil
			u.lastSeen = time.Now()
		}
		h.mu.Unlock()
	}()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("X-Accel-Buffering", "no")
	rc := http.NewResponseController(w)
	write := func(b []byte) bool {
		_, err := w.Write(b)
		return err == nil && rc.Flush() == nil
	}
	if !write([]byte("retry: 2000\n\n")) || !write(snapshot) {
		return
	}

	ping := time.NewTicker(pingEvery)
	defer ping.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-evict:
			return
		case ev := <-u.queue:
			if !write(ev) {
				return
			}
		case <-ping.C:
			if !write([]byte(": ping\n\n")) {
				return
			}
		}
	}
}

// send relays an opaque payload to another user. The server only checks the
// envelope; message bodies are ciphertext it cannot read.
func (h *hub) send(w http.ResponseWriter, r *http.Request) {
	u := h.auth(r)
	if u == nil {
		http.Error(w, "Unknown session.", http.StatusUnauthorized)
		return
	}
	var req struct {
		To   string          `json:"to"`
		Type string          `json:"type"`
		Data json.RawMessage `json:"data"`
	}
	if !decode(w, r, &req) {
		return
	}
	if !relayTypes[req.Type] {
		http.Error(w, "Unknown message type.", http.StatusBadRequest)
		return
	}

	h.mu.Lock()
	allowed := u.limit.allow()
	to := h.byName[strings.ToLower(req.To)]
	h.mu.Unlock()

	switch {
	case !allowed:
		http.Error(w, "Slow down.", http.StatusTooManyRequests)
		return
	case to == nil || to == u:
		http.Error(w, "That user is offline.", http.StatusNotFound)
		return
	}
	select {
	case to.queue <- frame(map[string]any{"k": "relay", "from": u.name, "type": req.Type, "data": req.Data}):
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "That user isn't keeping up. Try again.", http.StatusServiceUnavailable)
	}
}

func (h *hub) leave(w http.ResponseWriter, r *http.Request) {
	if u := h.auth(r); u != nil {
		h.mu.Lock()
		if h.byToken[u.token] == u {
			h.remove(u)
		}
		h.mu.Unlock()
	}
	w.WriteHeader(http.StatusNoContent)
}

func frame(v any) []byte {
	b, _ := json.Marshal(v)
	return append(append([]byte("data: "), b...), '\n', '\n')
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes)).Decode(v); err != nil {
		http.Error(w, "Bad request.", http.StatusBadRequest)
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func newToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// secure adds headers that lock the page down to its own files: no third-party
// requests, no framing, no referrers and no caching.
func secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hdr := w.Header()
		hdr.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		hdr.Set("Referrer-Policy", "no-referrer")
		hdr.Set("X-Content-Type-Options", "nosniff")
		hdr.Set("X-Frame-Options", "DENY")
		hdr.Set("Cross-Origin-Opener-Policy", "same-origin")
		hdr.Set("Cross-Origin-Resource-Policy", "same-origin")
		hdr.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), interest-cohort=()")
		hdr.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "listen address; keep it on loopback and let Tor reach it")
	flag.Parse()

	static, err := fs.Sub(webFiles, "web")
	if err != nil {
		log.Fatal(err)
	}
	h := newHub()
	go h.run()

	mux := http.NewServeMux()
	mux.Handle("GET /", http.FileServerFS(static))
	mux.HandleFunc("POST /api/join", h.join)
	mux.HandleFunc("GET /api/events", h.events)
	mux.HandleFunc("POST /api/send", h.send)
	mux.HandleFunc("POST /api/leave", h.leave)

	srv := &http.Server{
		Addr:              *addr,
		Handler:           secure(mux),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    8 << 10,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	log.Printf("onion-chat listening on http://%s", *addr)
	log.Fatal(srv.ListenAndServe())
}
