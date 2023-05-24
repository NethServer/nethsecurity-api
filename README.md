# ns-api-server

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
- `POST /login`: used for login.

    REQ
    ```json
     Content-Type: application/json

     {"username": "root", "password": "Nethesis,1234"}    
    ```

    RES
    ```json
     HTTP/1.1 200 OK
     Content-Type: application/json; charset=utf-8

     {"code": 200, "expire": "2023-05-25T14:04:03.734920987Z", "token": "eyJh...E-f0"}
    ```
- `POST /logout`: used for logout.

    REQ
    ```json
     Content-Type: application/json
     Authorization: Bearer <JWT_TOKEN>
    ```

    RES
    ```json
     HTTP/1.1 200 OK
     Content-Type: application/json; charset=utf-8

     {"code": 200}
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

     {"code": 200, "expire": "2023-05-25T14:04:03.734920987Z", "token": "eyJh...E-f0"}
    ```

### 2FA
- `POST /2FA/otp-verify`
- `GET /2FA`
- `DELETE /2FA`
- `GET /2FA/qr-code`

### ubus
- `POST /ubus/call`

   REQ
    ```json
     Content-Type: application/json
     Authorization: Bearer <JWT_TOKEN>

     {"path": "luci", "method": "getRealtimeStats", "payload": {"mode": "conntrack"}}
    ```

    RES
    ```json
     HTTP/1.1 200 OK
     Content-Type: application/json; charset=utf-8

     {"code": 200, "data": {...}, "message": "[UBUS] call action success"}
    ```