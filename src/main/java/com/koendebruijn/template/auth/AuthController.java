package com.koendebruijn.template.auth;

import com.koendebruijn.template.user.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;

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
    public HashMap<String, String> refreshToken(@CookieValue("refresh_token") String refreshToken, HttpServletResponse response) {

        HashMap<String, String> tokens = authService.refreshToken(refreshToken);

        Cookie cookie = new Cookie("refresh_token", tokens.get("refreshToken"));
        tokens.remove("refreshToken");
        cookie.setHttpOnly(true);
        response.addCookie(cookie);


        return tokens;
    }
}
