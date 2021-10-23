package com.koendebruijn.template.user.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

public class UserNotFoundException extends ResponseStatusException {
    public UserNotFoundException(String username) {
        super(HttpStatus.NOT_FOUND, "user with username: " + username + " not found");
    }
}
