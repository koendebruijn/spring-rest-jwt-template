package com.koendebruijn.template.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.koendebruijn.template.auth.AuthService;
import com.koendebruijn.template.auth.dto.LoginRequest;
import com.koendebruijn.template.token.TokenService;
import com.koendebruijn.template.token.dto.TokenResponse;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final TokenService tokenService;
    private final AuthService authService;


    @SneakyThrows
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        String json = request.getReader().lines().collect(Collectors.joining(System.lineSeparator()));

        LoginRequest login = objectMapper.readValue(json, LoginRequest.class);

        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(login.getUsername(), login.getPassword());

        return authenticationManager.authenticate(token);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws IOException {
        User user = (User) authentication.getPrincipal();

        String subject = user.getUsername();
        List<String> roles = user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList());

        TokenResponse tokenResponse = new TokenResponse(tokenService.signAccessToken(subject, roles), tokenService.signRefreshToken(subject, roles));
        authService.createResponse(response, tokenResponse);
    }



}
