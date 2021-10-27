package com.koendebruijn.template.token;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.koendebruijn.template.user.User;
import com.koendebruijn.template.user.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@Slf4j
@Service
@RequiredArgsConstructor
public class TokenService {
    Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());
    private final UserService userService;

    public String signAccessToken(String subject, List<String> roles) {
        User user = userService.getUser(subject);

        String token = JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + 30 * 60 * 1000))
                .withIssuer(ServletUriComponentsBuilder.fromCurrentContextPath().build().toUriString())
                .withClaim("roles", roles)
                .sign(algorithm);

        user.setAccessToken(token);
        userService.updateUser(user);

        return token;
    }

    public void validateAccessToken() {
    }

    public String signRefreshToken(String subject, List<String> roles) {
        User user = userService.getUser(subject);

        String token = JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + 30 * 60 * 1000))
                .withIssuer(ServletUriComponentsBuilder.fromCurrentContextPath().build().toUriString())
                .withClaim("roles", roles)
                .sign(algorithm);

        user.setRefreshToken(token);
        userService.updateUser(user);

        return token;
    }

    public User verifyRefreshToken(String refreshToken) {

        DecodedJWT decodedJWT = decodeJTW(refreshToken);
        String username = decodedJWT.getSubject();
        User user = userService.getUser(username);

        if (!refreshToken.equals(user.getRefreshToken())) {
            throw new ResponseStatusException(UNAUTHORIZED);
        }

        return user;
    }

    private DecodedJWT decodeJTW(String token) throws IndexOutOfBoundsException {
        JWTVerifier verifier = JWT.require(algorithm).build();
        return verifier.verify(token);
    }

    private void handleJWTException(Exception exception, HttpServletResponse response) throws IOException {
        log.error("Error logging in {}", exception.getMessage());
        response.setStatus(FORBIDDEN.value());

        Map<String, String> error = new HashMap<>();
        error.put("errorMessage", exception.getMessage());
        response.setContentType(APPLICATION_JSON_VALUE);
        new ObjectMapper().writeValue(response.getOutputStream(), error);
    }
}
