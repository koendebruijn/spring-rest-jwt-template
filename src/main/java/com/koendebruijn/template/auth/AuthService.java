package com.koendebruijn.template.auth;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.koendebruijn.template.token.TokenService;
import com.koendebruijn.template.user.Role;
import com.koendebruijn.template.user.User;
import com.koendebruijn.template.user.UserService;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

import static java.util.Arrays.stream;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@Service
@Slf4j
@RequiredArgsConstructor
public class AuthService {
    private final Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());
    private final UserService userService;
    private final TokenService tokenService;


    public DecodedJWT decodeJTW(String token) {
        JWTVerifier verifier = JWT.require(algorithm).build();
        return verifier.verify(token);
    }

    public User getUserFromAuthHeader(String authorizationHeader) {
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            throw new RuntimeException("Refresh token is missing");
        }

        String refreshToken = authorizationHeader.substring("Bearer ".length());

        DecodedJWT decodedJWT = decodeJTW(refreshToken);

        String username = decodedJWT.getSubject();
        return userService.getUser(username);
    }

    public HashMap<String, String> refreshToken(String refreshToken) {
        User user = tokenService.verifyRefreshToken(refreshToken);
        String subject = user.getUsername();
        List<String> roles = user.getRoles().stream().map(Role::getName).collect(Collectors.toList());

        String newRefreshToken = tokenService.signRefreshToken(subject, roles);
        String newAccessToken = tokenService.signAccessToken(subject, roles);

        return new HashMap<>(){{
            put("accessToken", newAccessToken);
            put("refreshToken", newRefreshToken);
        }};
    }

    /**
     * @deprecated
     */
    public static void createResponse(HttpServletResponse response, String refreshToken, String accessToken) throws IOException {
        Map<String, String> tokens = new HashMap<>();
        tokens.put("accessToken", accessToken);

        Cookie cookie = new Cookie("refresh_token", refreshToken);
        cookie.setHttpOnly(true);
        response.addCookie(cookie);

        response.setContentType(APPLICATION_JSON_VALUE);
        new ObjectMapper().writeValue(response.getOutputStream(), tokens);
    }

    public void createTokens(HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain) throws ServletException, IOException {
        String authorizationHeader = request.getHeader(AUTHORIZATION);

        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            String token = authorizationHeader.substring("Bearer ".length());
            Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());
            JWTVerifier verifier = JWT.require(algorithm).build();
            DecodedJWT decodedJWT = verifier.verify(token);
            String username = decodedJWT.getSubject();
            String[] roles = decodedJWT.getClaim("roles").asArray(String.class);
            Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();

            stream(roles).forEach(role -> authorities.add(new SimpleGrantedAuthority(role)));

            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, null, authorities);
            SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            filterChain.doFilter(request, response);
        } catch (Exception exception) {
            handleJWTException(exception, response);
        }
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
