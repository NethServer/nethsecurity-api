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
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"

	"github.com/NethServer/nethsecurity-api/models"
	"github.com/NethServer/nethsecurity-api/response"
	"github.com/NethServer/nethsecurity-api/utils"

	"github.com/Jeffail/gabs/v2"
	"github.com/fatih/structs"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
)

// List, to check if path is allowed:
// this is a security measure to avoid direct calls to binaries
// that are not part of any package
var validPaths []string

func LoadValidPaths() {
	paths := make([]string, 0)
	files, err := os.ReadDir("/usr/libexec/rpcd")
	if err != nil {
		return
	}
	for _, file := range files {
		if strings.HasPrefix(file.Name(), "ns.") {
			path := "/usr/libexec/rpcd/" + file.Name()
			// execute opkg search path, if output is empty, the file does not belong to any package: don't add to valid paths
			out, err := exec.Command("/bin/opkg", "search", path).Output()
			if out != nil && err == nil {
				paths = append(paths, path)
			}
		}
	}
	// update valid paths only as last thing to avoid having an empty list during reload
	validPaths = paths
}

func UBusCallAction(c *gin.Context) {
	// parse request fields
	var jsonUBusCall models.UBusCallJSON
	var cmd *exec.Cmd
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

	// check if path starts with ns.
	if jsonUBusCall.Path[:3] == "ns." {
		// force base path to avoid calling other system binaries
		jsonUBusCall.Path = "/usr/libexec/rpcd/" + jsonUBusCall.Path
		// check if path is inside valid paths list
		if !utils.Contains(jsonUBusCall.Path, validPaths) {
			c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
				Code:    400,
				Message: "invalid path",
				Data:    jsonUBusCall.Path,
			}))
			return
		}

		cmd = exec.Command(jsonUBusCall.Path, "call", jsonUBusCall.Method)

		// execute direct script call
		stdin, err := cmd.StdinPipe()
		if err != nil {
			c.JSON(http.StatusInternalServerError, structs.Map(response.StatusBadRequest{
				Code:    500,
				Message: "ubus call action failed",
				Data:    err.Error(),
			}))
			return
		}

		io.WriteString(stdin, string(jsonPayload))
		stdin.Close()
	} else {
		// fallback to rpcd
		cmd = exec.Command("/bin/ubus", "-S", "-t", "300", "call", jsonUBusCall.Path, jsonUBusCall.Method, string(jsonPayload[:]))
	}

	// check errors
	out, err := cmd.CombinedOutput()
	if err != nil {
		c.JSON(http.StatusInternalServerError, structs.Map(response.StatusBadRequest{
			Code:    500,
			Message: "ubus call action failed",
			Data:    err.Error(),
		}))
		return
	}

	// parse output in a valid JSON
	jsonParsed, err := gabs.ParseJSON(out)
	if err != nil {
		c.JSON(http.StatusInternalServerError, structs.Map(response.StatusBadRequest{
			Code:    500,
			Message: "invalid JSON response",
			Data:    jsonParsed,
		}))
		return
	}

	// check errors in response
	errorMessage, errFound := jsonParsed.Path("error").Data().(string)
	if errFound {
		c.JSON(http.StatusInternalServerError, structs.Map(response.StatusBadRequest{
			Code:    500,
			Message: errorMessage,
			Data:    jsonParsed,
		}))
		return
	}

	// check validation error in response
	validationFound := jsonParsed.Exists("validation")
	if validationFound {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "validation_failed",
			Data:    jsonParsed,
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
