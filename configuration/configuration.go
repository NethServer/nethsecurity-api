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

package configuration

import (
	"os"
)

type Configuration struct {
	ListenAddress string `json:"listen_address"`

	SecretJWT  string `json:"secret_jwt"`
	Issuer2FA  string `json:"issuer_2fa"`
	SecretsDir string `json:"secrets_dir"`
	TokensDir  string `json:"tokens_dir"`

	StaticDir string `json:"static_dir"`
}

var Config = Configuration{}

func Init() {
	// read configuration from ENV
	if os.Getenv("LISTEN_ADDRESS") != "" {
		Config.ListenAddress = os.Getenv("LISTEN_ADDRESS")
	} else {
		Config.ListenAddress = "127.0.0.1:8080"
	}

	if os.Getenv("SECRET_JWT") != "" {
		Config.SecretJWT = os.Getenv("SECRET_JWT")
	} else {
		os.Stderr.WriteString("SECRET_JWT variable is empty. ")
		os.Exit(1)
	}

	if os.Getenv("ISSUER_2FA") != "" {
		Config.Issuer2FA = os.Getenv("ISSUER_2FA")
	} else {
		Config.Issuer2FA = "NethServer"
	}

	if os.Getenv("SECRETS_DIR") != "" {
		Config.SecretsDir = os.Getenv("SECRETS_DIR")
	} else {
		os.Stderr.WriteString("SECRETS_DIR variable is empty. ")
		os.Exit(1)
	}

	if os.Getenv("TOKENS_DIR") != "" {
		Config.TokensDir = os.Getenv("TOKENS_DIR")
	} else {
		os.Stderr.WriteString("TOKENS_DIR variable is empty. ")
		os.Exit(1)
	}

	if os.Getenv("STATIC_DIR") != "" {
		Config.StaticDir = os.Getenv("STATIC_DIR")
	} else {
		Config.StaticDir = "/var/run/ns-api-server"
	}
}
