# SpringBoot_Auth_Demo

A simple REST API that uses JWT Authentication

## Technologies

- Spring Boot
- Spring Security
- `java-jwt` library
- H2 Database
- Java 11
- Gradle
- `bcrypt` password hashing

## How it works

1. Users register for an account in the `/signup` endpoint
  - a valid user will return a response code of `200` and payload that looks like
     ```json
      {
        "Username": "username_of_created_user"
      }
    ```
  - an invalid user will return a response code of `400` and payload that looks like
  ```json
      {
        "Error: "some_error_with_account_creation_attempt"
      }
  ```
2. Users will attempt to sign in at the `/token` endpoint
  - request payload:
    ```json
    {
        "username": "someuser"
        "password": "notarealpassword"
    }
    ```
  - an invalid login will have a response code of `400` and payload of
    ```json
    {
        "error": "Invalid username or password"
    }
    ```
  - a valid attempt will have a response code of `200`, will return an HttpOnly cookie containing the JWT, and have a payload with the key `"token"` and a value containing the JWT
    - The payload here is only for one time use and should not be stored beyond that

3. Requests with the cookie to protected endpoints will now work until either the user logs out or the JWT expires
  - Both the cookie and JWT are set to expire after 30 minutes
    - This can be changed in the `jwt.maxage.seconds` value in `application.properties` file
  - The JWTFilter will read the JWT from the cookie and reject any invalid JWTs
4. User logs out from `/logout` endpoint or the JWT expires
  - Logout will add the JWT to a "blacklist" of tokens that can no longer be used

## Required Environment variables

`JWT_SCRT` needs to be set to any string before running the app
  - Linux/Mac: `export JWT_SCRT=[secretkey]`
    - replace `[secretkey]` with any string
  - in a production app, it's better to use keys than a secret password, but this demo is only for learning purposes
  - may replace this with keys in the future
