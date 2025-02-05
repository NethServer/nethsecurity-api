package middleware

import (
	"github.com/NethServer/nethsecurity-api/models"
	"github.com/NethServer/nethsecurity-api/response"
	"github.com/fatih/structs"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"net/http"
)

var protectedPaths = map[string][]string{
	"ns.ssh": {"add-key", "delete-key"},
}

// SudoUbusCallsMiddleware is a middleware that checks if the ubus call requires sudo privileges
// This needs to parse the request body to check the path and method of the ubus call, then check
// if it's in the protectedPaths map
func SudoUbusCallsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		var jsonUBusCall models.UBusCallJSON
		if err := c.ShouldBindBodyWith(&jsonUBusCall, binding.JSON); err != nil {
			c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
				Code:    400,
				Message: "request fields malformed",
				Data:    err.Error(),
			}))
			c.Abort()
			return
		}
		sudoRequired := false
		if protectedPaths[jsonUBusCall.Path] != nil {
			for _, method := range protectedPaths[jsonUBusCall.Path] {
				if method == jsonUBusCall.Method {
					sudoRequired = true
					break
				}
			}
		}
		if sudoRequired {
			SudoCheckToken(c)
		} else {
			c.Next()
		}
	}
}
