package api

import (
	"strings"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func SetupRouter(h *Handler) *gin.Engine {
	r := gin.Default()
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization"},
		AllowCredentials: true,
	}))
	r.Static("/static", "frontend/static")

	r.POST("/api/v1/auth/login", h.Login)
	r.GET("/health", func(c *gin.Context) { c.JSON(200, gin.H{"status": "ok"}) })

	api := r.Group("/api/v1", AuthMiddleware(), h.TroubleshootCaptureMiddleware())
	{
		api.GET("/auth/me", h.GetMe)

		// Users
		api.GET("/users", RoleMiddleware("super_admin"), h.GetUsers)
		api.POST("/users", RoleMiddleware("super_admin"), h.CreateUser)
		api.PUT("/users/:id", RoleMiddleware("super_admin"), h.UpdateUser)
		api.PUT("/users/:id/password", h.ChangePassword)
		api.DELETE("/users/:id", RoleMiddleware("super_admin"), h.DeleteUser)

		// Routers
		api.GET("/routers", h.GetRouters)
		api.GET("/routers/:id", h.GetRouter)
		api.POST("/routers", RoleMiddleware("admin"), h.CreateRouter)
		api.PUT("/routers/:id", RoleMiddleware("admin"), h.UpdateRouter)
		api.DELETE("/routers/:id", RoleMiddleware("admin"), h.DeleteRouter)
		api.POST("/routers/:id/test", RoleMiddleware("admin", "teknisi"), h.TestRouterConnection)
		api.POST("/routers/:id/test-snmp", RoleMiddleware("admin", "teknisi"), h.TestRouterSNMPConnection)
		api.POST("/routers/:id/sync", RoleMiddleware("admin", "teknisi"), h.SyncRouter)

		// Monitoring
		api.GET("/monitoring/stats", h.GetStats)
		api.GET("/monitoring/secrets", h.GetPPPSecrets)
		api.GET("/monitoring/router-status", h.GetRouterStatuses)
		api.GET("/monitoring/chart-data", h.GetChartData)
		api.GET("/pppoe/servers", h.GetPPPoEServers)
		api.GET("/pppoe/router/:id/profiles", RoleMiddleware("super_admin", "admin"), h.GetPPPProfiles)
		api.POST("/pppoe/users", RoleMiddleware("super_admin", "admin"), h.CreatePPPUser)
		api.PUT("/pppoe/users", RoleMiddleware("super_admin", "admin"), h.UpdatePPPUser)
		api.DELETE("/pppoe/users", RoleMiddleware("super_admin", "admin"), h.DeletePPPUser)
		api.GET("/user-monitoring/layout", RoleMiddleware("admin"), h.GetUserMonitoringLayout)
		api.PUT("/user-monitoring/layout", RoleMiddleware("admin"), h.SaveUserMonitoringLayout)
		api.GET("/user-monitoring/:id/ppp-interfaces", RoleMiddleware("admin"), h.GetUserMonitoringPPPInterfaces)
		api.POST("/monitoring/disconnect", RoleMiddleware("super_admin", "admin"), h.DisconnectUser)
		api.GET("/monitoring/user/:username", h.GetUserDetail)
		// Traffic
		api.GET("/traffic/:id/live", RoleMiddleware("admin", "teknisi"), h.GetTrafficLive)
		api.GET("/traffic/:id/history", RoleMiddleware("admin", "teknisi"), h.GetTrafficHistory)
		api.GET("/nms/:id/snmp/interfaces", RoleMiddleware("admin", "teknisi"), h.GetSNMPInterfaces)
		api.GET("/nms/:id/snmp/live", RoleMiddleware("admin", "teknisi"), h.GetSNMPLiveTraffic)
		api.GET("/nms/:id/snmp/history", RoleMiddleware("admin", "teknisi"), h.GetSNMPHistory)
		api.GET("/nms/layout", RoleMiddleware("admin", "teknisi"), h.GetNMSLayout)
		api.PUT("/nms/layout", RoleMiddleware("admin", "teknisi"), h.SaveNMSLayout)

		// NOC
		api.POST("/noc/ping/:id", RoleMiddleware("admin", "teknisi"), h.PingFromRouter)

		// Sync
		api.POST("/sync/all", RoleMiddleware("admin", "teknisi"), h.SyncAll)
		api.GET("/sync/status", h.GetSyncStatus)
		api.GET("/sync/settings", RoleMiddleware("admin"), h.GetSyncSettings)
		api.PUT("/sync/settings", RoleMiddleware("admin"), h.UpdateSyncSettings)
		api.GET("/sync/logs", h.GetSyncLogs)
		api.GET("/troubleshoot/logs", RoleMiddleware("admin", "teknisi"), h.GetTroubleshootLogs)
		api.DELETE("/troubleshoot/logs", RoleMiddleware("admin"), h.DeleteTroubleshootLogs)

		// Server
		api.GET("/system/server-info", h.GetServerInfo)

		if h.oltHandler != nil {
			api.POST("/olts", RoleMiddleware("super_admin", "admin"), h.oltHandler.CreateOLT)
			api.GET("/olts", RoleMiddleware("super_admin", "admin", "teknisi"), h.oltHandler.GetOLTs)
			api.GET("/olts/:id", RoleMiddleware("super_admin", "admin", "teknisi"), h.oltHandler.GetOLT)
			api.PUT("/olts/:id", RoleMiddleware("super_admin", "admin"), h.oltHandler.UpdateOLT)
			api.DELETE("/olts/:id", RoleMiddleware("super_admin", "admin"), h.oltHandler.DeleteOLT)
			api.POST("/olts/test-connection", RoleMiddleware("super_admin", "admin", "teknisi"), h.oltHandler.TestConnection)
			api.POST("/olts/:id/onus/sync", RoleMiddleware("super_admin", "admin", "teknisi"), h.oltHandler.StartONUSync)
			api.GET("/olts/:id/onus/sync-status", RoleMiddleware("super_admin", "admin", "teknisi"), h.oltHandler.GetONUSyncStatus)
			api.GET("/olts/:id/onus", RoleMiddleware("super_admin", "admin", "teknisi"), h.oltHandler.GetONUs)
			api.GET("/olts/:id/troubleshoot/raw-telnet", RoleMiddleware("super_admin", "admin"), h.oltHandler.GetRawTelnetDump)
			api.GET("/olts/:id/troubleshoot/telnet-command", RoleMiddleware("super_admin", "admin"), h.oltHandler.RunTelnetCommand)
			api.GET("/onus/:sn/detail", RoleMiddleware("super_admin", "admin", "teknisi"), h.oltHandler.GetONUDetail)
		}
	}
	if h.oltHandler != nil {
		apiCompat := r.Group("/api", AuthMiddleware(), h.TroubleshootCaptureMiddleware())
		{
			apiCompat.POST("/olts", RoleMiddleware("super_admin", "admin"), h.oltHandler.CreateOLT)
			apiCompat.GET("/olts", RoleMiddleware("super_admin", "admin", "teknisi"), h.oltHandler.GetOLTs)
			apiCompat.GET("/olts/:id", RoleMiddleware("super_admin", "admin", "teknisi"), h.oltHandler.GetOLT)
			apiCompat.PUT("/olts/:id", RoleMiddleware("super_admin", "admin"), h.oltHandler.UpdateOLT)
			apiCompat.DELETE("/olts/:id", RoleMiddleware("super_admin", "admin"), h.oltHandler.DeleteOLT)
			apiCompat.POST("/olts/test-connection", RoleMiddleware("super_admin", "admin", "teknisi"), h.oltHandler.TestConnection)
			apiCompat.POST("/olts/:id/onus/sync", RoleMiddleware("super_admin", "admin", "teknisi"), h.oltHandler.StartONUSync)
			apiCompat.GET("/olts/:id/onus/sync-status", RoleMiddleware("super_admin", "admin", "teknisi"), h.oltHandler.GetONUSyncStatus)
			apiCompat.GET("/olts/:id/onus", RoleMiddleware("super_admin", "admin", "teknisi"), h.oltHandler.GetONUs)
			apiCompat.GET("/olts/:id/troubleshoot/raw-telnet", RoleMiddleware("super_admin", "admin"), h.oltHandler.GetRawTelnetDump)
			apiCompat.GET("/olts/:id/troubleshoot/telnet-command", RoleMiddleware("super_admin", "admin"), h.oltHandler.RunTelnetCommand)
			apiCompat.GET("/onus/:sn/detail", RoleMiddleware("super_admin", "admin", "teknisi"), h.oltHandler.GetONUDetail)
		}
	}
	r.GET("/", h.ServeApp)
	r.NoRoute(func(c *gin.Context) {
		path := c.Request.URL.Path
		if strings.HasPrefix(path, "/api/") || strings.HasPrefix(path, "/static/") {
			c.JSON(404, gin.H{"success": false, "message": "Route not found"})
			return
		}
		if c.Request.Method == "GET" {
			h.ServeApp(c)
			return
		}
		c.JSON(404, gin.H{"success": false, "message": "Route not found"})
	})
	return r
}
