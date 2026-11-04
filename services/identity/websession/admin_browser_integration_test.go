package websession

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/evilsysadmin/shadowops-infra/services/identity/issuance"
	"go.mongodb.org/mongo-driver/v2/bson"
)

func TestChromiumAdminInventoryJourney(t *testing.T) {
	if os.Getenv("IDENTITY_BROWSER_TEST") != "1" {
		t.Skip("explicit local browser test not configured")
	}
	f := setupMode(t, true)
	_, err := f.db.Collection("pending_accounts").UpdateOne(context.Background(), bson.M{"_id": testSubject}, bson.M{"$set": bson.M{"source": "shadowops-identity", "alias_key": "admin_browser", "created_at": time.Now().UTC(), "role": "admin"}})
	if err != nil {
		t.Fatal(err)
	}
	var extra []any
	for n := 1; n <= 20; n++ {
		extra = append(extra, bson.M{"_id": fmt.Sprintf("22222222-2222-4222-8222-%012x", n), "environment": "staging", "source": "shadowops-identity", "alias_key": fmt.Sprintf("player_%02d", n), "state": "active", "credentials_disabled": false, "session_version": int64(1), "created_at": time.Now().UTC()})
	}
	if _, err := f.db.Collection("pending_accounts").InsertMany(context.Background(), extra); err != nil {
		t.Fatal(err)
	}
	_, err = f.db.Collection("staging_cka_tokens").InsertOne(context.Background(), bson.M{"_id": "synthetic-recent-access", "issuer": "https://id-staging.shadowops.dpdns.org", "subject": testSubject, "session_version": int64(1), "audience": "chronicles", "issued_at": time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.db.RunCommand(context.Background(), bson.D{{Key: "create", Value: "staging_admin_recent_access"}, {Key: "viewOn", Value: "staging_cka_tokens"}, {Key: "pipeline", Value: bson.A{bson.D{{Key: "$project", Value: bson.D{{Key: "_id", Value: 0}, {Key: "issuer", Value: 1}, {Key: "subject", Value: 1}, {Key: "session_version", Value: 1}, {Key: "audience", Value: 1}, {Key: "issued_at", Value: 1}}}}}}}).Err(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.db.Collection("staging_admin_recent_access").Drop(context.Background()) })
	history := f.db.Collection("staging_application_access_history")
	if err := history.Drop(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = history.Drop(context.Background()) })
	if _, err := history.InsertOne(context.Background(), bson.M{"_id": testSubject + ":chronicles", "environment": "staging", "subject": testSubject, "application": "chronicles", "first_at": time.Now().Add(-48 * time.Hour).UTC(), "last_at": time.Now().Add(-24 * time.Hour).UTC()}); err != nil {
		t.Fatal(err)
	}
	audit := f.db.Collection("admin_inventory_audit")
	if err := audit.Drop(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = audit.Drop(context.Background()) })
	reader, err := issuance.NewStagingAdminInventoryReader(f.client, true, true)
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := NewStagingAdminInventoryHandler(reader)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:19443")
	if err != nil {
		t.Fatal(err)
	}
	edge := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin", "/assets/admin.css", "/assets/admin.js":
			StagingAdminPage(w, r)
		case AdminInventoryPath:
			inventory.ServeHTTP(w, r)
		default:
			f.h.ServeHTTP(w, r)
		}
	}))
	edge.Listener.Close()
	edge.Listener = listener
	edge.StartTLS()
	defer edge.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "node", "testdata/admin-browser.cjs")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("admin browser journey failed: %v\n%s", err, output)
	}
	t.Log(string(output))
}
