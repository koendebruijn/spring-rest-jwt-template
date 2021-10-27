package com.koendebruijn.template.auth;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.koendebruijn.template.user.User;
import com.koendebruijn.template.user.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.util.*;

import static org.springframework.http.HttpStatus.UNAUTHORIZED;

@Slf4j
@Service
@RequiredArgsConstructor
public class TokenService {
    final Algorithm algorithm = Algorithm.HMAC256("SECRET".getBytes());
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

    public boolean verifyAccessToken(String accessToken) {

        DecodedJWT decodedJWT = decodeJTW(accessToken);
        String username = decodedJWT.getSubject();
        User user = userService.getUser(username);

        if (!accessToken.equals(user.getAccessToken())) {
            return false;
        }

        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
        user.getRoles().forEach(role -> authorities.add(new SimpleGrantedAuthority(role.getName())));

        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, null, authorities);
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);

        return true;
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

    public DecodedJWT decodeJTW(String token) throws IndexOutOfBoundsException {
        JWTVerifier verifier = JWT.require(algorithm).build();
        return verifier.verify(token);
    }

}
