package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"
)

type Flow struct {
	SrcIP    string `json:"src_ip"`
	DstIP    string `json:"dst_ip"`
	SrcPort  int    `json:"src_port"`
	DstPort  int    `json:"dst_port"`
	Protocol string `json:"protocol"`
}

type TraceRequest struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Mode        string `json:"mode"`
	Flow        Flow   `json:"flow"`
}

type Hop struct {
	Node      string `json:"node"`
	Interface string `json:"interface"`
	TTL       int    `json:"ttl"`
}

type TracePath struct {
	Hops []Hop `json:"hops"`
}

type TraceResponse struct {
	Source          string      `json:"source"`
	Destination     string      `json:"destination"`
	Mode            string      `json:"mode"`
	ECMPWidth       int         `json:"ecmp_width"`
	Paths           []TracePath `json:"paths"`
	SelectedPath    *TracePath  `json:"selected_path,omitempty"`
	HashContext     string      `json:"hash_context"`
	TimestampUnixMS int64       `json:"timestamp_unix_ms"`
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"service": "ecmp-trace",
		"status":  "running",
	})
}

func traceHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	var req TraceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Placeholder response until the ETR probing engine is wired in.
	// Next step is to replace this with extracted probe logic.
	pathA := TracePath{
		Hops: []Hop{
			{Node: req.Source, Interface: "Ethernet49", TTL: 1},
			{Node: "spine-01", Interface: "Ethernet1", TTL: 2},
			{Node: req.Destination, Interface: "loopback", TTL: 3},
		},
	}

	pathB := TracePath{
		Hops: []Hop{
			{Node: req.Source, Interface: "Ethernet50", TTL: 1},
			{Node: "spine-02", Interface: "Ethernet1", TTL: 2},
			{Node: req.Destination, Interface: "loopback", TTL: 3},
		},
	}

	resp := TraceResponse{
		Source:          req.Source,
		Destination:     req.Destination,
		Mode:            req.Mode,
		ECMPWidth:       2,
		Paths:           []TracePath{pathA, pathB},
		SelectedPath:    &pathA,
		HashContext:     "5_tuple",
		TimestampUnixMS: time.Now().UnixMilli(),
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func main() {
	http.HandleFunc("/", healthHandler)
	http.HandleFunc("/trace", traceHandler)

	log.Println("ecmp trace service listening on :8081")
	log.Fatal(http.ListenAndServe(":8081", nil))
}
