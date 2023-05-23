/*
 * Copyright (C) 2023 Nethesis S.r.l.
 * http://www.nethesis.it - info@nethesis.it
 *
 * This file is part of NethServer project.
 *
 * NethServer is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License,
 * or any later version.
 *
 * NethServer is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with NethServer.  If not, see COPYING.
 *
 * author: Edoardo Spadoni <edoardo.spadoni@nethesis.it>
 */

package middleware

import (
	"time"

	"github.com/pkg/errors"

	"github.com/fatih/structs"
	"github.com/gin-gonic/gin"

	jwt "github.com/appleboy/gin-jwt/v2"

	"github.com/NethServer/ns-api-server/configuration"
	"github.com/NethServer/ns-api-server/methods"
	"github.com/NethServer/ns-api-server/models"
	"github.com/NethServer/ns-api-server/response"
	"github.com/NethServer/ns-api-server/utils"
)

type login struct {
	Username string `form:"username" json:"username" binding:"required"`
	Password string `form:"password" json:"password" binding:"required"`
}

var jwtMiddleware *jwt.GinJWTMiddleware
var identityKey = "id"

func InstanceJWT() *jwt.GinJWTMiddleware {
	if jwtMiddleware == nil {
		jwtMiddleware := InitJWT()
		return jwtMiddleware
	}
	return jwtMiddleware
}

func InitJWT() *jwt.GinJWTMiddleware {
	// define jwt middleware
	authMiddleware, errDefine := jwt.New(&jwt.GinJWTMiddleware{
		Realm:       "nethserver",
		Key:         []byte(configuration.Config.SecretJWT),
		Timeout:     time.Hour * 24, // 1 day
		MaxRefresh:  time.Hour * 24, // 1 day
		IdentityKey: identityKey,
		Authenticator: func(c *gin.Context) (interface{}, error) {
			// check login credentials exists
			var loginVals login
			if err := c.ShouldBind(&loginVals); err != nil {
				return "", jwt.ErrMissingLoginValues
			}

			// set login credentials
			username := loginVals.Username
			password := loginVals.Password

			// check login
			err := methods.CheckAuthentication(username, password)
			if err != nil {
				utils.LogError(errors.Wrap(err, "[AUTH] authentication failed for user "+username))

				// store login fail action TODO

				// return JWT error
				return nil, jwt.ErrFailedAuthentication
			}

			// store audit login ok action TODO

			// return user auth model
			return &models.UserAuthorizations{
				Username: username,
			}, nil

		},
		PayloadFunc: func(data interface{}) jwt.MapClaims {
			// read current user
			if user, ok := data.(*models.UserAuthorizations); ok {
				// check if user require 2fa
				var required = methods.GetUserSecret(user.Username) != ""

				// create claims map
				return jwt.MapClaims{
					identityKey: user.Username,
					"role":      "",
					"actions":   []string{},
					"2fa":       required,
				}
			}

			// return claims map
			return jwt.MapClaims{}
		},
		IdentityHandler: func(c *gin.Context) interface{} {
			// handle identity and extract claims
			claims := jwt.ExtractClaims(c)

			// create user object
			user := &models.UserAuthorizations{
				Username: claims[identityKey].(string),
				Role:     "admin",
				Actions:  nil,
			}

			// return user
			return user
		},
		Authorizator: func(data interface{}, c *gin.Context) bool {
			// check token validation
			claims, _ := InstanceJWT().GetClaimsFromJWT(c)
			token, _ := InstanceJWT().ParseToken(c)

			// check if token exists
			if !methods.CheckTokenValidation(claims["id"].(string), token.Raw) {
				// not authorized
				return false
			}

			// store audit authorization action TODO

			// authorized
			return true
		},
		LoginResponse: func(c *gin.Context, code int, token string, t time.Time) {
			//get claims
			tokenObj, _ := InstanceJWT().ParseTokenString(token)
			claims := jwt.ExtractClaimsFromToken(tokenObj)

			// set token to valid, if not 2FA
			if !claims["2fa"].(bool) {
				methods.SetTokenValidation(claims["id"].(string), token)
			}

			// return 200 OK
			c.JSON(200, gin.H{"code": 200, "expire": t, "token": token})
		},
		LogoutResponse: func(c *gin.Context, code int) {
			//get claims
			tokenObj, _ := InstanceJWT().ParseToken(c)
			claims := jwt.ExtractClaimsFromToken(tokenObj)

			// set token to invalid
			methods.RemoveTokenValidation(claims["id"].(string), tokenObj.Raw)

			// reutrn 200 OK
			c.JSON(200, gin.H{"code": 200})
		},
		Unauthorized: func(c *gin.Context, code int, message string) {
			// response not authorized
			c.JSON(code, structs.Map(response.StatusUnauthorized{
				Code:    code,
				Message: message,
				Data:    nil,
			}))
			return
		},
		TokenLookup:   "header: Authorization, token: jwt",
		TokenHeadName: "Bearer",
		TimeFunc:      time.Now,
	})

	// check middleware errors
	if errDefine != nil {
		utils.LogError(errors.Wrap(errDefine, "[AUTH] middleware definition error"))
	}

	// init middleware
	errInit := authMiddleware.MiddlewareInit()

	// check error on initialization
	if errInit != nil {
		utils.LogError(errors.Wrap(errInit, "[AUTH] middleware initialization error"))
	}

	// return object
	return authMiddleware
}
