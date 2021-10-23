package com.koendebruijn.template.user.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

public class RoleNotFoundException extends ResponseStatusException {
    public RoleNotFoundException(String roleName) {
        super(HttpStatus.NOT_FOUND, roleName + " not found");
    }
}
