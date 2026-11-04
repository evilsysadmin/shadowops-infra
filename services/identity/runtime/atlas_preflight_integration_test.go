package runtime

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestServiceRuntimeAtlasPreflightVerifiesBothMongoRoles(t *testing.T) {
	cfg := runtimeFixture(t)
	cfg.AdminInventoryMongoURI = os.Getenv("IDENTITY_RUNTIME_INVENTORY_HISTORY_URI")
	checkLocalRuntimeURI(t, cfg.AdminInventoryMongoURI)
	cfg.MongoURI = os.Getenv("IDENTITY_RUNTIME_HISTORY_URI")
	checkLocalRuntimeURI(t, cfg.MongoURI)
	cfg.AdminInventoryAccessHistory = true
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := PreflightStagingConnections(ctx, cfg); err != nil {
		t.Fatal("valid separate TLS users rejected", err)
	}
	invalid := cfg
	invalid.AdminInventoryMongoURI = os.Getenv("IDENTITY_RUNTIME_INVENTORY_URI")
	checkLocalRuntimeURI(t, invalid.AdminInventoryMongoURI)
	if err := PreflightStagingConnections(ctx, invalid); err == nil {
		t.Fatal("inventory missing history privilege accepted")
	}
	invalid = cfg
	invalid.MongoURI = os.Getenv("IDENTITY_RUNTIME_BROAD_URI")
	checkLocalRuntimeURI(t, invalid.MongoURI)
	if err := PreflightStagingConnections(ctx, invalid); err == nil {
		t.Fatal("overprivileged runtime accepted")
	}
	invalid = cfg
	invalid.AdminInventoryMongoURI = ""
	if err := PreflightStagingConnections(ctx, invalid); err == nil {
		t.Fatal("missing inventory connection accepted")
	}
}
