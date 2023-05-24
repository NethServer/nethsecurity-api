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
	"os"
	"strconv"
	"time"
)

func LogError(err error) {
	os.Stderr.WriteString(err.Error() + "\n")
}

func Contains(a string, values []string) bool {
	for _, b := range values {
		if b == a {
			return true
		}
	}
	return false
}

func EpochToHumanDate(epochTime int) string {
	i, err := strconv.ParseInt(strconv.Itoa(epochTime), 10, 64)
	if err != nil {
		return "-"
	}
	tm := time.Unix(i, 0)
	return tm.Format("2006-01-02 15:04:05")
}
