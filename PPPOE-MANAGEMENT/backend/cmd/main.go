package main

import (
	"context"
	"log"
	"mikrotik-ppp-management/config"
	"mikrotik-ppp-management/internal/api"
	olthandler "mikrotik-ppp-management/internal/handler"
	"mikrotik-ppp-management/internal/migrations"
	"mikrotik-ppp-management/internal/repository"
	"mikrotik-ppp-management/internal/service"
	oltsnmp "mikrotik-ppp-management/internal/snmp"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
	"github.com/sirupsen/logrus"
	gormmysql "gorm.io/driver/mysql"
	"gorm.io/gorm"
)

func main() {
	cfg := config.Load()
	if loc, err := time.LoadLocation("Asia/Jakarta"); err == nil {
		time.Local = loc
	}

	var db *sqlx.DB
	var err error
	for i := 0; i < 15; i++ {
		db, err = sqlx.Connect("mysql", cfg.DSN())
		if err == nil {
			break
		}
		log.Printf("DB not ready (%d/15): %v", i+1, err)
		time.Sleep(3 * time.Second)
	}
	if err != nil {
		log.Fatalf("DB connect failed: %v", err)
	}
	defer db.Close()
	maxOpen := cfg.DBMaxOpenConns
	if maxOpen <= 0 {
		maxOpen = 40
	}
	maxIdle := cfg.DBMaxIdleConns
	if maxIdle <= 0 {
		maxIdle = 10
	}
	if maxIdle > maxOpen {
		maxIdle = maxOpen
	}
	connLifetime := time.Duration(cfg.DBConnMaxLifetimeMinutes) * time.Minute
	if connLifetime <= 0 {
		connLifetime = 10 * time.Minute
	}
	db.SetMaxOpenConns(maxOpen)
	db.SetMaxIdleConns(maxIdle)
	db.SetConnMaxLifetime(connLifetime)
	if _, err := db.Exec("SET time_zone = '+07:00'"); err != nil {
		log.Printf("timezone warning: %v", err)
	}
	log.Println("Database connected")

	// Auto-migrate: create all tables if not exist
	if err := migrations.AutoMigrate(db); err != nil {
		log.Printf("Migration warning: %v", err)
	}

	gormDB, err := gorm.Open(gormmysql.Open(cfg.DSN()), &gorm.Config{})
	if err != nil {
		log.Fatalf("GORM MySQL connect failed: %v", err)
	}

	userRepo := repository.NewUserRepository(db)
	routerRepo := repository.NewRouterRepository(db)
	pppRepo := repository.NewPPPRepository(db)
	syncRepo := repository.NewSyncRepository(db)
	troubleshootRepo := repository.NewTroubleshootRepository(db)
	trafficRepo := repository.NewTrafficRepository(db)
	oltRepo := repository.NewOLTRepository(gormDB)
	if err := oltRepo.AutoMigrate(); err != nil {
		log.Fatalf("OLT migration failed: %v", err)
	}

	syncSvc := service.NewSyncService(routerRepo, pppRepo, syncRepo, trafficRepo)
	syncSvc.SetTroubleshootRepository(troubleshootRepo)
	syncSvc.Start()
	oltLogger := logrus.New()
	oltLogger.SetFormatter(&logrus.JSONFormatter{})
	oltSvc := service.NewOLTService(oltRepo, troubleshootRepo, oltsnmp.NewService(), oltLogger, time.Duration(cfg.OLTPollIntervalSeconds)*time.Second)
	oltSvc.StartWorker(context.Background())

	handler := api.NewHandler(userRepo, routerRepo, pppRepo, syncRepo, troubleshootRepo, trafficRepo, syncSvc)
	handler.SetOLTHandler(olthandler.NewOLTHandler(oltSvc))
	if appTemplate, err := api.LoadAppTemplate(); err != nil {
		log.Printf("Frontend template warning: %v", err)
	} else {
		handler.SetAppTemplate(appTemplate)
	}
	r := api.SetupRouter(handler)

	log.Printf("Server starting on :%s", cfg.AppPort)
	if err := r.Run(":" + cfg.AppPort); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
