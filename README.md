# nethsecurity-api

## Build
```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build
```

## Run
```bash
SECRET_JWT="<secret>" SECRETS_DIR="<secrets_dir>" TOKENS_DIR="<tokens_dir>" ./ns-api-server
```

Where:
- `SECRET_JWT`: is the secret used to sign JWT tokens
- `SECRETS_DIR`: is the directory where 2FA secrets are stored, must be persistent
- `TOKENS_DIR`: is the directory where valid JWT tokens are stored

## APIs
### Auth
- `POST /login`

    REQ
    ```json
     Content-Type: application/json

     {
       "username": "root",
       "password": "Nethesis,1234"
     }
    ```

    RES
    ```json
     HTTP/1.1 200 OK
     Content-Type: application/json; charset=utf-8

     {
       "code": 200,
       "expire": "2023-05-25T14:04:03.734920987Z",
       "token": "eyJh...E-f0"
     }
    ```
- `POST /logout`

    REQ
    ```json
     Content-Type: application/json
     Authorization: Bearer <JWT_TOKEN>
    ```

    RES
    ```json
     HTTP/1.1 200 OK
     Content-Type: application/json; charset=utf-8

     {
       "code": 200
     }
    ```
- `GET /refresh`

    REQ
    ```json
     Content-Type: application/json
     Authorization: Bearer <JWT_TOKEN>
    ```

    RES
    ```json
     HTTP/1.1 200 OK
     Content-Type: application/json; charset=utf-8

     {
       "code": 200,
       "expire": "2023-05-25T14:04:03.734920987Z",
       "token": "eyJh...E-f0"
     }
    ```

### 2FA
- `POST /2fa/otp-verify`

    REQ
    ```json
     Content-Type: application/json
     Authorization: Bearer <JWT_TOKEN>

     {
       "username": "root",
       "token": "eyJhbGc...VXT7l0",
       "otp": "435450"
     }
    ```

    RES
    ```json
     HTTP/1.1 200 OK
     Content-Type: application/json; charset=utf-8

     {
       "code": 200,
       "data": "eyJhbGc...VXT7l0",
       "message": "OTP verified"
     }
    ```

- `GET /2fa`

    REQ
    ```json
     Content-Type: application/json
     Authorization: Bearer <JWT_TOKEN>
    ```

    RES
    ```json
     HTTP/1.1 200 OK
     Content-Type: application/json; charset=utf-8

     {
       "code": 200,
       "data": false,
       "message": "2FA not set for this user"
     }
    ```
- `DELETE /2fa`

    REQ
    ```json
     Content-Type: application/json
     Authorization: Bearer <JWT_TOKEN>
    ```

    RES
    ```json
     HTTP/1.1 200 OK
     Content-Type: application/json; charset=utf-8

     {
       "code": 200,
       "data": false,
       "message": "2FA revocate successfully"
     }
    ```
- `GET /2fa/qr-code`

    REQ
    ```json
     Content-Type: application/json
     Authorization: Bearer <JWT_TOKEN>
    ```

    RES
    ```json
     HTTP/1.1 200 OK
     Content-Type: application/json; charset=utf-8

     {
       "code": 200,
       "data": {
           "key": "KRPTKOGMNO...37A4OCD7FG3D",
           "url": "otpauth://totp/NethServer:root?algorithm=SHA1&digits=6&issuer=NethServer&period=30&secret=KRPTKOGMNO...37A4OCD7FG3D"
     },
        "message": "QR code string"
     }
    ```

### ubus
- `POST /ubus/call`

   REQ
    ```json
     Content-Type: application/json
     Authorization: Bearer <JWT_TOKEN>

     {
       "path": "luci",
       "method": "getRealtimeStats",
       "payload": {
           "mode": "conntrack"
        }
     }
    ```

    RES
    ```json
     HTTP/1.1 200 OK
     Content-Type: application/json; charset=utf-8

     {
       "code": 200,
       "data": {...},
       "message": "[UBUS] call action success"
     }
    ```