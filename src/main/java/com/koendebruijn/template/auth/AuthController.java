package com.koendebruijn.template.auth;

import com.koendebruijn.template.auth.dto.TokenResponse;
import com.koendebruijn.template.user.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {
    private final AuthService authService;

    @GetMapping("/me")
    public User getMe(HttpServletRequest request) {
        return authService.getUserFromAuthHeader(request.getHeader(AUTHORIZATION));
    }

    @GetMapping("/refresh-token")
    public void refreshToken(@CookieValue("refresh_token") String refreshToken, HttpServletResponse response) throws IOException {

        TokenResponse tokens = authService.refreshToken(refreshToken);
        authService.createResponse(response, tokens);
    }

    @GetMapping("/logout")
    public void logout(@CookieValue(value = "refresh_token", defaultValue = "") String refreshToken, HttpServletResponse response) {

        if (refreshToken.isBlank()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        }

        Cookie deletedCookie = new Cookie("refresh_token", null);
        deletedCookie.setMaxAge(0);
        deletedCookie.setHttpOnly(true);

        authService.logout(refreshToken);

        response.addCookie(deletedCookie);
    }
}
