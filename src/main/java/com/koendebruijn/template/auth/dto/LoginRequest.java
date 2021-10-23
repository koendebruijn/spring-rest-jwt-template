package com.koendebruijn.template.auth.dto;

import lombok.Data;

@Data
public class LoginRequest {
    String password;
    String username;
}
