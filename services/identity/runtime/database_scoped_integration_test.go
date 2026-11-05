package runtime

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestServiceRuntimeDatabaseScopedMode(t *testing.T) {
	cfg := runtimeFixture(t)
	cfg.MongoURI = os.Getenv("IDENTITY_RUNTIME_BROAD_URI")
	checkLocalRuntimeURI(t, cfg.MongoURI)
	cfg.AdminInventoryMongoURI = os.Getenv("IDENTITY_RUNTIME_BROAD_SECOND_URI")
	checkLocalRuntimeURI(t, cfg.AdminInventoryMongoURI)
	cfg.AdminInventoryAccessHistory = true
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := PreflightStagingConnections(ctx, cfg); err == nil {
		t.Fatal("strict default accepted database-wide role")
	}
	cfg.MongoPrivilegeMode = "database-scoped"
	if err := PreflightStagingConnections(ctx, cfg); err != nil {
		t.Fatal("dedicated database-scoped users rejected", err)
	}
	service, err := NewStagingService(ctx, cfg)
	if err != nil {
		t.Fatal("database-scoped service did not start", err)
	}
	defer service.Client.Disconnect(context.Background())
	defer service.AdminClient.Disconnect(context.Background())
	cluster := cfg
	cluster.MongoURI = os.Getenv("IDENTITY_RUNTIME_CLUSTER_BROAD_URI")
	checkLocalRuntimeURI(t, cluster.MongoURI)
	if err := PreflightStagingConnections(ctx, cluster); err == nil {
		t.Fatal("cluster-wide access accepted")
	}
	clusterInventory := cfg
	clusterInventory.AdminInventoryMongoURI = os.Getenv("IDENTITY_RUNTIME_CLUSTER_BROAD_URI")
	checkLocalRuntimeURI(t, clusterInventory.AdminInventoryMongoURI)
	if err := PreflightStagingConnections(ctx, clusterInventory); err == nil {
		t.Fatal("cluster-wide inventory accepted")
	}
	recent := cfg
	recent.AdminInventoryRecentAccess = true
	if err := PreflightStagingConnections(ctx, recent); err == nil {
		t.Fatal("unconfigured recent access view accepted")
	}
	same := cfg
	same.AdminInventoryMongoURI = same.MongoURI
	if err := PreflightStagingConnections(ctx, same); err == nil {
		t.Fatal("shared runtime/inventory user accepted")
	}
	wrong := cfg
	wrong.MongoPrivilegeMode = "unsupported"
	if err := PreflightStagingConnections(ctx, wrong); err == nil {
		t.Fatal("unknown privilege mode accepted")
	}
}
