/*
 * Copyright (C) 2023 Nethesis S.r.l.
 * http://www.nethesis.it - info@nethesis.it
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * author: Edoardo Spadoni <edoardo.spadoni@nethesis.it>
 */

package logs

import (
	"log/syslog"
)

var Logs *syslog.Writer

func Init(name string) {
	// init syslog writer
	sysLog, err := syslog.New(syslog.LOG_WARNING|syslog.LOG_DAEMON, name)

	// check error on init
	if err != nil {
		sysLog.Crit("[CRITICAL][LOGS] Failed to init syslog logs: " + err.Error())
	}

	// assign writer to Logs var
	Logs = sysLog
}
