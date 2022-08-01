package com.piedpiper.authdemo.JWT;

import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.JWTCreationException;

import java.time.Instant;

@Component
public class JWTUtil {

    public JWTUtil() {}

    @Value("${jwt.secret}")
    private String secret;

    public String generateToken(String username) throws IllegalArgumentException, JWTCreationException {
        Instant now = Instant.now();
        Algorithm algo = Algorithm.HMAC256(secret);
        return JWT.create()
                .withSubject("User Details")
                .withClaim("username", username)
                .withIssuedAt(now)
                .withExpiresAt(now.plusSeconds(1800))
                .withIssuer("com.piedpiper.authdemo")
                .sign(algo);
    }
    public String validateTokenAndGetSubject(String token) throws JWTVerificationException {
        JWTVerifier verifier = JWT.require(Algorithm.HMAC256(secret))
                .withSubject("User Details")
                .withIssuer("com.piedpiper.authdemo")
                .build();
        DecodedJWT jwt = verifier.verify(token);
        return jwt.getClaim("username").asString();
    }
}
