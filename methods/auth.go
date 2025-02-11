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
	"errors"
	"fmt"
	"github.com/pquerna/otp/totp"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"strings"

	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/fatih/structs"
	"github.com/gin-gonic/gin"
	jwtl "github.com/golang-jwt/jwt"

	"github.com/NethServer/nethsecurity-api/configuration"
	"github.com/NethServer/nethsecurity-api/logs"
	"github.com/NethServer/nethsecurity-api/models"
	"github.com/NethServer/nethsecurity-api/response"
	"github.com/NethServer/nethsecurity-api/utils"
)

var (
	// ErrorCredentials is returned when the credentials are invalid
	ErrorCredentials = errors.New("invalid_credentials")
	// ErrorMissingOTP is returned when the OTP is missing
	ErrorMissingOTP = errors.New("required")
	// ErrorInvalidOTP is returned when the OTP is invalid
	ErrorInvalidOTP = errors.New("invalid_otp")
)

func CheckAuthentication(username string, password string, twoFa string) error {
	// define login object
	login := models.UserLogin{
		Username: username,
		Password: password,
		Timeout:  1,
	}
	jsonLogin, _ := json.Marshal(login)

	// execute login command on ubus
	_, err := exec.Command("/bin/ubus", "call", "session", "login", string(jsonLogin)).Output()
	if err != nil {
		return ErrorCredentials
	}

	// password is good, need the 2FA code?
	secret := GetUserSecret(username)
	if len(secret) != 0 {
		if len(twoFa) == 0 {
			return ErrorMissingOTP
		}
		valid := totp.Validate(twoFa, secret)
		if !valid {
			return ErrorInvalidOTP
		}
	}
	return nil
}

func Start2FaProcedure(c *gin.Context) {
	// get claims from token
	claims := jwt.ExtractClaims(c)
	username := claims["id"].(string)

	// check if 2FA is already enabled
	status, err := IsTwoFaEnabledForUser(username)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, structs.Map(response.StatusInternalServerError{
			Code:    500,
			Message: "issues fetching 2FA status",
			Data:    err.Error(),
		}))
		return
	}
	if status {
		c.AbortWithStatusJSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "2FA already enabled",
			Data:    nil,
		}))
		return
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      configuration.Config.Issuer2FA,
		AccountName: username,
	})
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "failed to generate 2FA",
			Data:    err,
		}))
		return
	}

	err = SetTemporarySecret(username, key.Secret())
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "cannot set secret for user",
			Data:    err,
		}))
		return
	}

	c.JSON(http.StatusOK, structs.Map(response.StatusOK{
		Code:    200,
		Message: "QR code string",
		Data:    gin.H{"url": key.URL(), "key": key.Secret()},
	}))
	return
}

func Enable2Fa(c *gin.Context) {
	var enable2FaRequest models.EnableTwoFa
	err := c.ShouldBind(&enable2FaRequest)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "request fields malformed",
			Data:    err.Error(),
		}))
		return
	}

	// get claims from token
	claims := jwt.ExtractClaims(c)
	username := claims["id"].(string)
	// fetch token from storage
	secret, err := GetTemporarySecret(username)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, structs.Map(response.StatusInternalServerError{
			Code:    500,
			Message: "issues with temporary secret",
			Data:    err.Error(),
		}))
		return
	}
	// check if the OTP is valid
	valid := totp.Validate(enable2FaRequest.OTP, secret)
	if !valid {
		c.AbortWithStatusJSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    400,
			Message: "validation_failed",
			Data: utils.ValidationResponse{
				Validation: utils.ValidationBag{
					Errors: []utils.ValidationEntry{
						{
							Message:   "invalid_otp",
							Parameter: "otp",
							Value:     "",
						},
					},
				},
			},
		}))
		return
	}

	err = SetUserSecret(username)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, structs.Map(response.StatusInternalServerError{
			Code:    500,
			Message: "issues with setting user secret",
			Data:    err,
		}))
		return
	}
	codes, err := GenerateRecoveryCodes(username)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, structs.Map(response.StatusInternalServerError{
			Code:    500,
			Message: "issues with generating recovery codes",
			Data:    err,
		}))
		return
	}

	logs.Logs.Println("[INFO][2FA] 2FA has been enabled for user " + username)

	c.JSON(http.StatusOK, structs.Map(response.StatusOK{
		Code:    200,
		Message: "2FA enabled",
		Data: gin.H{
			"recovery_codes": codes,
		},
	}))
}

// CheckOtp checks if the OTP is valid for the user, checks and validates the OTP even against the recovery codes,
// deleting them if needed
func CheckOtp(username string, otp string) (bool, error) {
	// get secret
	secret := GetUserSecret(username)
	// validate otp
	valid := totp.Validate(otp, secret)
	if !valid {
		// check if the OTP is a recovery code
		codes, err := os.ReadFile(configuration.Config.SecretsDir + "/" + username + "/codes")
		if err != nil {
			return false, err
		}
		// parse endline separated codes
		recoveryCodes := strings.Split(string(codes), "\n")
		// check if the otp is a recovery code
		for i, code := range recoveryCodes {
			if code == otp {
				// remove the recovery code
				recoveryCodes = append(recoveryCodes[:i], recoveryCodes[i+1:]...)
				// re-save codes to file
				file, err := os.OpenFile(configuration.Config.SecretsDir+"/"+username+"/codes", os.O_WRONLY|os.O_CREATE, 0600)
				defer file.Close()
				if err != nil {
					return false, err
				}
				_, err = file.WriteString(strings.Join(recoveryCodes, "\n"))
				if err != nil {
					return false, err
				}
				// return true if the otp is a recovery code
				return true, nil
			}
		}
		// return false if the otp is not a recovery code
		return false, nil
	} else {
		return true, nil
	}
}

// GenerateRecoveryCodes generates 8 recovery codes for the user, and stores them in a file before returning them
func GenerateRecoveryCodes(username string) ([]string, error) {
	// generate 8 recovery codes composed by 6 digits
	var codes []string
	for i := 0; i < 8; i++ {
		code := utils.RandomDigitString(6)
		codes = append(codes, code)
	}
	// save codes to file
	file, err := os.OpenFile(configuration.Config.SecretsDir+"/"+username+"/codes", os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	_, err = file.WriteString(strings.Join(codes, "\n"))
	if err != nil {
		return nil, err
	}

	return codes, nil
}

func Get2FAStatus(c *gin.Context) {
	// get claims from token and check if 2FA is enabled
	claims := jwt.ExtractClaims(c)
	status, err := IsTwoFaEnabledForUser(claims["id"].(string))
	// check if impossible to retrieve user 2FA status
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, structs.Map(response.StatusInternalServerError{
			Code:    500,
			Message: "error in get 2FA status",
			Data:    err.Error(),
		}))
		return
	}

	c.JSON(http.StatusOK, structs.Map(response.StatusOK{
		Code:    200,
		Message: "2FA status",
		Data: gin.H{
			"enabled": status,
		},
	}))
}

func Del2FAStatus(c *gin.Context) {
	// get claims from token
	claims := jwt.ExtractClaims(c)
	// revocate secret
	errRevocate := os.Remove(configuration.Config.SecretsDir + "/" + claims["id"].(string) + "/secret")
	if errRevocate != nil {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    403,
			Message: "error in revocate 2FA for user",
			Data:    nil,
		}))
		return
	}

	// revocate recovery codes
	errRevocateCodes := os.Remove(configuration.Config.SecretsDir + "/" + claims["id"].(string) + "/codes")
	if errRevocateCodes != nil {
		c.JSON(http.StatusBadRequest, structs.Map(response.StatusBadRequest{
			Code:    403,
			Message: "error in delete 2FA recovery codes",
			Data:    nil,
		}))
		return
	}

	// response
	c.JSON(http.StatusOK, structs.Map(response.StatusOK{
		Code:    200,
		Message: "2FA revocate successfully",
		Data:    "",
	}))
}

func IsTwoFaEnabledForUser(username string) (bool, error) {
	// check if secret file exists
	_, err := os.Stat(configuration.Config.SecretsDir + "/" + username + "/secret")
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func GetUserSecret(username string) string {
	// get secret
	secret, err := os.ReadFile(configuration.Config.SecretsDir + "/" + username + "/secret")

	// handle error
	if err != nil {
		return ""
	}

	// return string
	return string(secret[:])
}

func SetTemporarySecret(username string, secret string) error {
	secretsDirectory := configuration.Config.SecretsDir + "/" + username
	// check if dir exists, otherwise create it
	_, err := os.Stat(secretsDirectory)
	if err != nil {
		if os.IsNotExist(err) {
			err = os.MkdirAll(secretsDirectory, 0700)
			if err != nil {
				return err
			}
		} else {
			return err
		}
	}
	secretFile := secretsDirectory + "/temp_secret"
	// open file, and write secret
	file, err := os.OpenFile(secretFile, os.O_WRONLY|os.O_CREATE, 0600)
	defer file.Close()
	if err != nil {
		return err
	}
	_, err = file.WriteString(secret)

	return err
}

func GetTemporarySecret(username string) (string, error) {
	secret, err := os.ReadFile(configuration.Config.SecretsDir + "/" + username + "/temp_secret")
	if err != nil {
		return "", err
	} else if len(secret) == 0 {
		return "", errors.New("temporary secret empty")
	}
	return string(secret), nil
}

// SetUserSecret moves the temporary secret to the final secret file
func SetUserSecret(username string) error {
	tempSecretLocation := configuration.Config.SecretsDir + "/" + username + "/temp_secret"
	tempSecret, err := os.ReadFile(tempSecretLocation)
	if err != nil {
		return err
	}
	secretLocation := configuration.Config.SecretsDir + "/" + username + "/secret"
	// open file, and write secret
	file, err := os.OpenFile(secretLocation, os.O_WRONLY|os.O_CREATE, 0600)
	defer file.Close()
	if err != nil {
		return err
	}
	_, err = file.Write(tempSecret)
	if err != nil {
		return err
	}
	// remove temporary secret
	err = os.Remove(tempSecretLocation)
	return err
}

func CheckTokenValidation(username string, token string) bool {
	// read whole file
	secrestListB, err := os.ReadFile(configuration.Config.TokensDir + "/" + username)
	if err != nil {
		return false
	}
	secrestList := string(secrestListB)

	// check whether secret list contains token
	return strings.Contains(secrestList, token)
}

func SetTokenValidation(username string, token string) bool {
	// open file
	f, _ := os.OpenFile(configuration.Config.TokensDir+"/"+username, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	defer f.Close()

	// write file with tokens
	_, err := f.WriteString(token + "\n")

	// check error
	return err == nil
}

func DelTokenValidation(username string, token string) bool {
	// read whole file
	secrestListB, errR := ioutil.ReadFile(configuration.Config.TokensDir + "/" + username)
	if errR != nil {
		return false
	}
	secrestList := string(secrestListB)

	// match token to remove
	res := strings.Replace(secrestList, token, "", 1)

	// open file
	f, _ := os.OpenFile(configuration.Config.TokensDir+"/"+username, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	defer f.Close()

	// write file with tokens
	_, err := f.WriteString(strings.TrimSpace(res) + "\n")

	// check error
	return err == nil
}

func ValidateAuth(tokenString string, ensureTokenExists bool) bool {
	// convert token string and validate it
	if tokenString != "" {
		token, err := jwtl.Parse(tokenString, func(token *jwtl.Token) (interface{}, error) {
			// validate the alg
			if _, ok := token.Method.(*jwtl.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}

			// return secret
			return []byte(configuration.Config.SecretJWT), nil
		})

		if err != nil {
			logs.Logs.Println("[ERR][JWT] error in JWT token validation: " + err.Error())
			return false
		}

		if claims, ok := token.Claims.(jwtl.MapClaims); ok && token.Valid {
			if claims["id"] != nil {
				if ensureTokenExists {
					username := claims["id"].(string)

					if !CheckTokenValidation(username, tokenString) {
						logs.Logs.Println("[ERR][JWT] error JWT token not found")
						return false
					}
				}
				return true
			}
		} else {
			logs.Logs.Println("[ERR][JWT] error in JWT token claims")
			return false
		}
	}
	return false
}

func GetRecoveryCodes(username string) []string {
	// create empty array
	var recoveryCodes []string

	// check if recovery codes exists
	codesB, _ := os.ReadFile(configuration.Config.SecretsDir + "/" + username + "/codes")

	// check length
	if len(string(codesB[:])) == 0 {

		// get secret
		secret := GetUserSecret(username)

		// get recovery codes
		if len(string(secret)) > 0 {
			// execute oathtool to get recovery codes
			out, err := exec.Command("/usr/bin/oathtool", "-w", "4", "-b", secret).Output()

			// check errors
			if err != nil {
				return recoveryCodes
			}

			// open file
			f, _ := os.OpenFile(configuration.Config.SecretsDir+"/"+username+"/codes", os.O_WRONLY|os.O_CREATE, 0600)
			defer f.Close()

			// write file with secret
			_, _ = f.WriteString(string(out[:]))

			// assign binary output
			codesB = out
		}

	}

	// parse output
	recoveryCodes = strings.Split(string(codesB[:]), "\n")

	// remove empty element, the last one
	if recoveryCodes[len(recoveryCodes)-1] == "" {
		recoveryCodes = recoveryCodes[:len(recoveryCodes)-1]
	}

	// return codes
	return recoveryCodes
}

func UpdateRecoveryCodes(username string, codes []string) bool {
	// open file
	f, _ := os.OpenFile(configuration.Config.SecretsDir+"/"+username+"/codes", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	defer f.Close()

	// write file with secret
	codes = append(codes, "")
	_, err := f.WriteString(strings.Join(codes[:], "\n"))

	// check error
	return err == nil
}

func DeleteExpiredTokens() {
	// create new tokens list
	var validTokens []string

	// read tokens directory
	usernames, err := ioutil.ReadDir(configuration.Config.TokensDir)

	// check read error
	if err != nil {
		logs.Logs.Println("[ERR][JWT] Failed to read tokens dir " + configuration.Config.TokensDir + ". Error: " + err.Error())
	}

	// list usernames
	for _, username := range usernames {
		// read whole file
		tokenstListB, err := ioutil.ReadFile(configuration.Config.TokensDir + "/" + username.Name())

		// check error
		if err != nil {
			logs.Logs.Println("[ERR][JWT] Failed to read tokens file " + configuration.Config.TokensDir + "/" + username.Name() + ". Error: " + err.Error())
		}

		// get string file
		tokensList := string(tokenstListB)

		// convert to array
		tokens := strings.Split(tokensList, "\n")

		// remove empty elem
		if tokens[len(tokens)-1] == "" {
			tokens = tokens[:len(tokens)-1]
		}

		// loop all tokens
		for _, token := range tokens {
			// validate token
			valid := ValidateAuth(token, false)

			// add only valid tokens
			if valid {
				token = strings.TrimSpace(token)
				validTokens = append(validTokens, token)
			}
		}

		// rewrite file with only valid tokens
		f, _ := os.OpenFile(configuration.Config.TokensDir+"/"+username.Name(), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
		defer f.Close()

		// compose string
		writeTokens := strings.Join(validTokens[:], "\n")

		// write file with tokens
		_, errWrite := f.WriteString(writeTokens + "\n")

		// check error
		if errWrite != nil {
			logs.Logs.Println("[ERR][JWT] Failed to write new tokens file " + configuration.Config.TokensDir + "/" + username.Name() + ". Error: " + errWrite.Error())
		}
	}

}
