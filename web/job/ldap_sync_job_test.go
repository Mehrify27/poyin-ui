package job

import (
	"encoding/json"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/database/model"
)

func TestLdapSyncJobClientsToJSONEscaping(t *testing.T) {
	j := NewLdapSyncJob()
	c := j.buildClient(nil, `alice"quote\slash@example.com`, 5, 1, 2)
	if c.ID == "" {
		t.Fatal("buildClient(nil) should assign a default UUID")
	}

	raw := j.clientsToJSON([]model.Client{c})
	var parsed struct {
		Clients []model.Client `json:"clients"`
	}
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		t.Fatalf("clientsToJSON produced invalid JSON %q: %v", raw, err)
	}
	if len(parsed.Clients) != 1 || parsed.Clients[0].Email != c.Email {
		t.Fatalf("round-trip mismatch: %+v", parsed.Clients)
	}
}
