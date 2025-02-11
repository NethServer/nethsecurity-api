/*
 * Copyright (C) 2023 Nethesis S.r.l.
 * http://www.nethesis.it - info@nethesis.it
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * author: Edoardo Spadoni <edoardo.spadoni@nethesis.it>
 */

package utils

import (
	"math/rand"
	"strconv"
	"time"
)

func Contains(a string, values []string) bool {
	for _, b := range values {
		if b == a {
			return true
		}
	}
	return false
}

func Remove(a string, values []string) []string {
	for i, v := range values {
		if v == a {
			return append(values[:i], values[i+1:]...)
		}
	}
	return values
}

func EpochToHumanDate(epochTime int) string {
	i, err := strconv.ParseInt(strconv.Itoa(epochTime), 10, 64)
	if err != nil {
		return "-"
	}
	tm := time.Unix(i, 0)
	return tm.Format("2006-01-02 15:04:05")
}

var digitTable = [...]byte{'1', '2', '3', '4', '5', '6', '7', '8', '9', '0'}

func RandomDigitString(max int) string {
	b := make([]byte, max)
	for i := range b {
		b[i] = digitTable[rand.Intn(10)]
	}
	return string(b)
}

type ValidationEntry struct {
	Message   string `json:"message" structs:"message"`
	Value     string `json:"value" structs:"value"`
	Parameter string `json:"parameter" structs:"parameter"`
}

type ValidationBag struct {
	Errors []ValidationEntry `json:"errors" structs:"errors"`
}

type ValidationResponse struct {
	Validation ValidationBag `json:"validation" structs:"validation"`
}
