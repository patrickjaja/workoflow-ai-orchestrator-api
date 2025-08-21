package database

import (
	"gorm.io/gorm"
)

// GormAdapter wraps gorm.DB to implement our Database interface
type GormAdapter struct {
	db *gorm.DB
}

// NewGormAdapter creates a new GORM database adapter
func NewGormAdapter(db *gorm.DB) Database {
	return &GormAdapter{db: db}
}

// DB returns the underlying GORM database instance
func (g *GormAdapter) DB() *gorm.DB {
	return g.db
}

// Close closes the database connection
func (g *GormAdapter) Close() error {
	sqlDB, err := g.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

// Ping verifies the database connection
func (g *GormAdapter) Ping() error {
	sqlDB, err := g.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Ping()
}

// AutoMigrate runs auto migrations
func (g *GormAdapter) AutoMigrate() error {
	return Migrate(g.db)
}