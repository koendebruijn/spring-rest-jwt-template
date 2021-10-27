package com.koendebruijn.template.auth;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.koendebruijn.template.token.TokenService;
import com.koendebruijn.template.token.dto.TokenResponse;
import com.koendebruijn.template.user.Role;
import com.koendebruijn.template.user.User;
import com.koendebruijn.template.user.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@Service
@Slf4j
@RequiredArgsConstructor
public class AuthService {
    private final UserService userService;
    private final TokenService tokenService;



    public User getUserFromAuthHeader(String authorizationHeader) {
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            throw new RuntimeException("Access token is missing");
        }

        String token = authorizationHeader.substring("Bearer ".length());

        DecodedJWT decodedJWT = tokenService.decodeJTW(token);

        String username = decodedJWT.getSubject();
        return userService.getUser(username);
    }

    public TokenResponse refreshToken(String refreshToken) {
        User user = tokenService.verifyRefreshToken(refreshToken);
        String subject = user.getUsername();
        List<String> roles = user.getRoles().stream().map(Role::getName).collect(Collectors.toList());

        String newRefreshToken = tokenService.signRefreshToken(subject, roles);
        String newAccessToken = tokenService.signAccessToken(subject, roles);

        return new TokenResponse(newAccessToken, newRefreshToken);
    }

    public void createResponse(HttpServletResponse response, TokenResponse tokens) throws IOException {
        Cookie cookie = new Cookie("refresh_token", tokens.getRefreshToken());
        cookie.setHttpOnly(true);
        response.addCookie(cookie);
        response.setContentType(APPLICATION_JSON_VALUE);

        new ObjectMapper().writeValue(response.getOutputStream(), tokens);
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
