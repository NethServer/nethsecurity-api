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

package response

type LoginRequestJWT struct {
	Username string `json:"username" example:"edoardo" structs:"username"`
	Password string `json:"password" example:"Nethesis,1234" structs:"password"`
}

type LoginResponseJWT struct {
	Code   int    `json:"code" example:"200" structs:"code"`
	Token  string `json:"token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhY3Rpb25zIjpbXSwiZXhwIjoxNjE5NTM0OTQ4LCJpZCI6ImVkb2FyZG8iLCJvcmlnX2lhdCI6MTYxODkzMDE0OCwicm9sZSI6IiJ9.bNRFa7MCQK-rTczOjLveXEWBqhjK-FWhnUPD3_ixcCI"  structs:"token"`
	Expire string `json:"expire" example:"2021-04-27T16:49:08+02:00" structs:"expire"`
}

type StatusOK struct {
	Code    int         `json:"code" example:"200" structs:"code"`
	Message string      `json:"message" example:"Success" structs:"message"`
	Data    interface{} `json:"data" structs:"data"`
}

type StatusCreated struct {
	Code    int         `json:"code" example:"201" structs:"code"`
	Message string      `json:"message" example:"Created" structs:"message"`
	Data    interface{} `json:"data" structs:"data"`
}

type StatusBadRequest struct {
	Code    int         `json:"code" example:"400" structs:"code"`
	Message string      `json:"message" example:"Bad request" structs:"message"`
	Data    interface{} `json:"data" structs:"data"`
}

type StatusUnauthorized struct {
	Code    int         `json:"code" example:"401" structs:"code"`
	Message string      `json:"message" example:"Unauthorized" structs:"message"`
	Data    interface{} `json:"data" structs:"data"`
}

type StatusForbidden struct {
	Code    int         `json:"code" example:"403" structs:"code"`
	Message string      `json:"message" example:"Forbidden" structs:"message"`
	Data    interface{} `json:"data" structs:"data"`
}

type StatusNotFound struct {
	Code    int         `json:"code" example:"404" structs:"code"`
	Message string      `json:"message" example:"Not found" structs:"message"`
	Data    interface{} `json:"data" structs:"data"`
}

type StatusInternalServerError struct {
	Code    int         `json:"code" example:"500" structs:"code"`
	Message string      `json:"message" example:"Internal server error" structs:"message"`
	Data    interface{} `json:"data" structs:"data"`
}

type StatusServiceUnavailable struct {
	Code    int         `json:"code" example:"503" structs:"code"`
	Message string      `json:"message" example:"Service unavailable" structs:"message"`
	Data    interface{} `json:"data" structs:"data"`
}
