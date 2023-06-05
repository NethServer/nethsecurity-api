/*
 * Copyright (C) 2023 Nethesis S.r.l.
 * http://www.nethesis.it - info@nethesis.it
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * author: Edoardo Spadoni <edoardo.spadoni@nethesis.it>
 */

package methods

import (
	"encoding/json"
	"net/http"
	"os/exec"

	"github.com/NethServer/nethsecurity-api/models"
	"github.com/NethServer/nethsecurity-api/response"

	"github.com/Jeffail/gabs/v2"
	"github.com/fatih/structs"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
)

func UBusCallAction(c *gin.Context) {
	// parse request fields
	var jsonUBusCall models.UBusCallJSON
	if err := c.ShouldBindBodyWith(&jsonUBusCall, binding.JSON); err != nil {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "request fields malformed",
			Data:    err.Error(),
		}))
		return
	}

	// convert payload to JSON
	jsonPayload, _ := json.Marshal(jsonUBusCall.Payload)

	// execute login command on ubus
	out, err := exec.Command("/bin/ubus", "-S", "call", jsonUBusCall.Path, jsonUBusCall.Method, string(jsonPayload[:])).Output()

	// check errors
	if err != nil {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "ubus call action failed",
			Data:    err.Error(),
		}))
		return
	}

	// parse output in a valid JSON
	jsonParsed, _ := gabs.ParseJSON(out)

	// check errors in response
	errorMessage, errFound := jsonParsed.Path("error").Data().(string)
	if errFound {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "ubus call action failed",
			Data:    "payload: " + errorMessage,
		}))
		return
	}

	// return 200 OK with data
	c.JSON(http.StatusOK, structs.Map(response.StatusOK{
		Code:    200,
		Message: "ubus call action success",
		Data:    jsonParsed,
	}))
}
