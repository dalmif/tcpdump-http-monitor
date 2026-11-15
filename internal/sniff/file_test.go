package sniff

import (
	"context"
	"os"
	"testing"
	"time"

	"httpmonitor/internal/flow"
)

// TestPcapFile processes a real capture: SNIFF_PCAP=/path/to/file.pcap go test -run PcapFile -v
func TestPcapFile(t *testing.T) {
	path := os.Getenv("SNIFF_PCAP")
	if path == "" {
		t.Skip("SNIFF_PCAP not set")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	store := flow.NewStore(10000)
	New(store, Config{}).Process(context.Background(), f, os.Getenv("SNIFF_DEDUP") != "0")
	time.Sleep(time.Second)
	for _, fl := range store.All() {
		t.Logf("%d %s %s %s %s %d %s%s %s", fl.ID, fl.Kind, fl.State, fl.Client, fl.Method, fl.Status, fl.Host, fl.Path, fl.Error)
	}
}
