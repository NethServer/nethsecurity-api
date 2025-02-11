package sudo

import (
	"github.com/NethServer/nethsecurity-api/methods"
	"github.com/NethServer/nethsecurity-api/middleware"
	"github.com/NethServer/nethsecurity-api/models"
	"github.com/NethServer/nethsecurity-api/response"
	"github.com/NethServer/nethsecurity-api/utils"
	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/fatih/structs"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"net/http"
)

// EnableSudo Function to be called in an authenticated route, returns a JWT token with sudo privileges
func EnableSudo(c *gin.Context) {
	// Extract claims from JWT
	claims := jwt.ExtractClaims(c)
	// Get username and 2FA status from claims
	username := claims["id"].(string)
	twoFa, _ := methods.IsTwoFaEnabledForUser(username)

	if twoFa {
		var jsonRequest struct {
			TwoFa string `json:"two_fa" structs:"two_fa"`
		}
		err := c.ShouldBindWith(&jsonRequest, binding.JSON)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
				Code:    http.StatusBadRequest,
				Message: "validation_failed",
				Data:    err.Error(),
			}))
			return
		}
		check, err := methods.CheckOtp(username, jsonRequest.TwoFa)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, structs.Map(response.StatusInternalServerError{
				Code:    http.StatusInternalServerError,
				Message: "Impossible to check OTP",
				Data:    err.Error(),
			}))
			return
		}
		if !check {
			c.AbortWithStatusJSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
				Code:    http.StatusBadRequest,
				Message: "validation_failed",
				Data: utils.ValidationResponse{
					Validation: utils.ValidationBag{
						Errors: []utils.ValidationEntry{
							{
								Message:   "invalid_otp",
								Parameter: "two_fa",
								Value:     "",
							},
						},
					},
				},
			}))
			return
		}
	} else {
		// Check if password sent is valid
		var jsonRequest struct {
			Password string `json:"password" structs:"password"`
		}
		err := c.ShouldBindWith(&jsonRequest, binding.JSON)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
				Code:    http.StatusBadRequest,
				Message: "validation_failed",
				Data:    nil,
			}))
			return
		}
		fail := methods.CheckAuthentication(username, jsonRequest.Password, "")
		if fail != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
				Code:    http.StatusBadRequest,
				Message: "validation_failed",
				Data: utils.ValidationResponse{
					Validation: utils.ValidationBag{
						Errors: []utils.ValidationEntry{
							{
								Message:   "invalid_password",
								Parameter: "password",
								Value:     "",
							},
						},
					},
				},
			}))
			return
		}
	}
	token, _, err := middleware.InstanceJWT().TokenGenerator(&models.UserAuthorizations{
		Username:      username,
		SudoRequested: true,
	})
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, structs.Map(response.StatusInternalServerError{
			Code:    http.StatusInternalServerError,
			Message: "Impossible to generate token",
		}))
		return
	}
	methods.SetTokenValidation(username, token)
	c.JSON(http.StatusOK, structs.Map(response.StatusOK{
		Message: "sudo_enabled",
		Data: struct {
			Token string `structs:"token"`
		}{
			Token: token,
		},
	}))
}
