/*
 * Copyright (C) 2023 Nethesis S.r.l.
 * http://www.nethesis.it - info@nethesis.it
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * author: Edoardo Spadoni <edoardo.spadoni@nethesis.it>
 */

package main

import (
	"io/ioutil"
	"net/http"

	"github.com/fatih/structs"
	"github.com/gin-contrib/cors"
	"github.com/gin-contrib/gzip"
	"github.com/gin-contrib/static"
	"github.com/gin-gonic/gin"

	"github.com/NethServer/ns-api-server/configuration"
	"github.com/NethServer/ns-api-server/methods"
	"github.com/NethServer/ns-api-server/middleware"
	"github.com/NethServer/ns-api-server/response"
)

// @title Nextsecurity Controller API Server
// @version 1.0
// @description Nextsecurity Controller API Server is used to create tasks across the nodes
// @termsOfService https://nethserver.org/terms/

// @contact.name NethServer Developer Team
// @contact.url https://nethserver.org/support

// @license.name GNU GENERAL PUBLIC LICENSE

// @host localhost:8080
// @schemes http
// @BasePath /api

func main() {
	// init configuration
	configuration.Init()

	// disable log to stdout when running in release mode
	if gin.Mode() == gin.ReleaseMode {
		gin.DefaultWriter = ioutil.Discard
	}

	// init routers
	router := gin.Default()

	// add default compression
	router.Use(gzip.Gzip(gzip.DefaultCompression))

	// cors configuration only in debug mode GIN_MODE=debug (default)
	if gin.Mode() == gin.DebugMode {
		// gin gonic cors conf
		corsConf := cors.DefaultConfig()
		corsConf.AllowHeaders = []string{"Authorization", "Content-Type", "Accept"}
		corsConf.AllowAllOrigins = true
		router.Use(cors.New(corsConf))
	}

	// define static file endpoint
	router.Use(static.Serve("/", static.LocalFile(configuration.Config.StaticDir, false)))

	// define api group
	api := router.Group("/api")

	// define login and logout endpoint
	api.POST("/login", middleware.InstanceJWT().LoginHandler)
	api.POST("/logout", middleware.InstanceJWT().LogoutHandler)

	// 2FA APIs
	api.POST("/2FA/otp-verify", methods.OTPVerify)

	// define JWT middleware
	api.Use(middleware.InstanceJWT().MiddlewareFunc())
	{
		// refresh handler
		api.GET("/refresh", middleware.InstanceJWT().RefreshHandler)

		// ubus wrapper
		api.POST("/ubus/call", methods.UBusCallAction)

		// 2FA APIs
		api.GET("/2FA", methods.Get2FAStatus)
		api.DELETE("/2FA", methods.Del2FAStatus)
		api.GET("/2FA/qr-code", methods.QRCode)
	}

	// handle missing endpoint
	router.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, structs.Map(response.StatusNotFound{
			Code:    404,
			Message: "API not found",
			Data:    nil,
		}))
	})

	// run server
	router.Run(configuration.Config.ListenAddress)
}
