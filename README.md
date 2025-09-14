# JWKS-server
A RESTful JWKS server implementation in Go that provides public keys for JWT verification.

## Features

- RSA key pair generation with unique Key IDs (kid)
- Key expiry management
- RESTful JWKS endpoint serving only non-expired keys
- Authentication endpoint issuing JWTs
- Support for expired JWT generation via query parameter
- Comprehensive test suite with >80% coverage

## Endpoints

- `GET /.well-known/jwks.json` - Returns JWKS with non-expired public keys
- `POST /auth` - Returns a signed JWT
- `POST /auth?expired=true` - Returns a JWT signed with expired key

## Running

```bash
go mod tidy
go run main.go
