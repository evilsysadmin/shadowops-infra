package websession

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/evilsysadmin/shadowops-infra/services/identity/admininventory"
	"github.com/evilsysadmin/shadowops-infra/services/identity/issuance"
	"go.mongodb.org/mongo-driver/v2/bson"
)

func TestAdminInventoryTransportUsesRealIdentitySession(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	audit := f.db.Collection("admin_inventory_audit")
	if err := audit.Drop(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = audit.Drop(context.Background()) })
	_, err := f.db.Collection("pending_accounts").UpdateOne(ctx, bson.M{"_id": testSubject}, bson.M{"$set": bson.M{"source": "shadowops-identity", "alias_key": "alice", "created_at": time.Now().UTC(), "role": "user"}})
	if err != nil {
		t.Fatal(err)
	}
	cookie := f.login(t, f.web)
	reader, err := issuance.NewStagingAdminInventoryReader(f.client, false, false)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewStagingAdminInventoryHandler(reader)
	if err != nil {
		t.Fatal(err)
	}
	request := func() *httptest.ResponseRecorder {
		r := adminInventoryRequest()
		r.Header.Del("Cookie")
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	if w := request(); w.Code != http.StatusUnauthorized {
		t.Fatal("ordinary account got inventory", w.Code)
	}
	_, err = f.db.Collection("pending_accounts").UpdateOne(ctx, bson.M{"_id": testSubject}, bson.M{"$set": bson.M{"role": "admin"}})
	if err != nil {
		t.Fatal(err)
	}
	w := request()
	if w.Code != http.StatusOK {
		t.Fatal("admin request failed", w.Code, w.Body.String())
	}
	var page admininventory.Page
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil || len(page.Accounts) != 1 || page.Accounts[0].Name != "alice" || page.Accounts[0].CurrentSessions != 1 {
		t.Fatal("incorrect inventory", page, err)
	}
	n, err := audit.CountDocuments(ctx, bson.M{"actor": testSubject, "action": "list_accounts"})
	if err != nil || n != 1 {
		t.Fatal("missing audit", n, err)
	}
	if err := f.issuer.Logout(ctx, cookie.Value); err != nil {
		t.Fatal(err)
	}
	if w = request(); w.Code != http.StatusUnauthorized {
		t.Fatal("logged-out session got inventory", w.Code)
	}
}
