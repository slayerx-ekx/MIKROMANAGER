package main

import (
	"fmt"
	"log"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"

	"mikrotik-ppp-management/config"
	"mikrotik-ppp-management/internal/api"
	"mikrotik-ppp-management/internal/migrations"
	"mikrotik-ppp-management/internal/repository"
	"mikrotik-ppp-management/internal/service"
)

func main() {
	cfg := config.Load()

	// Connect to database with retry
	var db *sqlx.DB
	var err error
	for i := 0; i < 30; i++ {
		db, err = sqlx.Connect("mysql", cfg.DSN())
		if err == nil {
			break
		}
		log.Printf("DB connection failed (attempt %d/30): %v", i+1, err)
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		log.Fatalf("Failed to connect to database after 30 attempts: %v", err)
	}
	defer db.Close()

	db.SetMaxOpenConns(cfg.DBMaxOpenConns)
	db.SetMaxIdleConns(cfg.DBMaxIdleConns)
	db.SetConnMaxLifetime(time.Duration(cfg.DBConnMaxLifetimeMinutes) * time.Minute)

	log.Println("Database connected successfully")

	// Run migrations
	if err := migrations.AutoMigrate(db); err != nil {
		log.Fatalf("Migration failed: %v", err)
	}

	// Initialize repositories
	userRepo := repository.NewUserRepository(db)
	routerRepo := repository.NewRouterRepository(db)
	pppRepo := repository.NewPPPRepository(db)
	syncRepo := repository.NewSyncRepository(db)
	troubleshootRepo := repository.NewTroubleshootRepository(db)
	trafficRepo := repository.NewTrafficRepository(db)

	// Initialize sync service
	syncSvc := service.NewSyncService(routerRepo, pppRepo, syncRepo, trafficRepo)
	syncSvc.SetTroubleshootRepository(troubleshootRepo)
	syncSvc.Start()

	// Initialize handler
	h := api.NewHandler(userRepo, routerRepo, pppRepo, syncRepo, troubleshootRepo, trafficRepo, syncSvc)

	// Load templates
	tmpl, err := api.LoadAppTemplate()
	if err != nil {
		log.Printf("Warning: Could not load app template: %v", err)
	} else {
		h.SetAppTemplate(tmpl)
	}

	// Setup router and start server
	r := api.SetupRouter(h)
	addr := fmt.Sprintf(":%s", cfg.AppPort)
	log.Printf("Server starting on %s (env: %s)", addr, cfg.AppEnv)
	if err := r.Run(addr); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
