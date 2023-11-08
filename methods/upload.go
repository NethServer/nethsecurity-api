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
	"net/http"
	"os"
	"path/filepath"

	"github.com/NethServer/nethsecurity-api/configuration"
	"github.com/NethServer/nethsecurity-api/response"
	"github.com/google/uuid"

	"github.com/fatih/structs"
	"github.com/gin-gonic/gin"
)

func Upload(c *gin.Context) {
	//check limit size
	var w http.ResponseWriter = c.Writer
	c.Request.Body = http.MaxBytesReader(w, c.Request.Body, configuration.Config.UploadFileMaxSize*1024*1024)
	c.Next()

	// get file
	file, err := c.FormFile("file")

	// check error
	if err != nil {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "file upload error. error on upload",
			Data:    err.Error(),
		}))
		return
	}

	// create directory if not exists
	_ = os.MkdirAll(configuration.Config.UploadFilePath, os.ModePerm)

	// get filename
	filename := filepath.Base(file.Filename)

	// set name with uuid to avoid overrides
	name := filename + "-" + uuid.New().String()

	// upload the file to specific directory and check error
	if err := c.SaveUploadedFile(file, configuration.Config.UploadFilePath+"/"+name); err != nil {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "file upload error. error on save",
			Data:    err.Error(),
		}))
		return
	}

	// return status ok
	c.JSON(http.StatusOK, structs.Map(response.StatusOK{
		Code:    200,
		Message: "file upload success",
		Data:    name,
	}))
}
