package runtime

import (
	"context"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"time"
)

// PreflightStagingConnections checks both users and a writable replica without
// creating indexes, accounts or sessions. Final-network and backup validation
// remain separate prerequisites.
func PreflightStagingConnections(ctx context.Context, cfg ServiceConfig) error {
	if ctx == nil || ctx.Err() != nil || cfg.AdminInventoryMongoURI == "" {
		return ErrUnsafeConfiguration
	}
	seed, _, tlsConfig, err := cfg.validate(time.Now())
	if err != nil {
		return err
	}
	defer clear(seed)
	connect := func(uri string) (*mongo.Client, error) {
		return mongo.Connect(options.Client().ApplyURI(uri).SetTLSConfig(tlsConfig).SetServerSelectionTimeout(3 * time.Second).SetConnectTimeout(3 * time.Second))
	}
	app, err := connect(cfg.MongoURI)
	if err != nil {
		return ErrServiceUnavailable
	}
	defer app.Disconnect(context.Background())
	if err := verifyRuntimeRole(ctx, app, cfg.AdminInventoryAccessHistory); err != nil {
		return err
	}
	if err := serviceReady(ctx, app); err != nil {
		return err
	}
	inventory, err := connect(cfg.AdminInventoryMongoURI)
	if err != nil {
		return ErrServiceUnavailable
	}
	defer inventory.Disconnect(context.Background())
	return verifyAdminInventoryRole(ctx, inventory, cfg.AdminInventoryRecentAccess, cfg.AdminInventoryAccessHistory)
}
