package com.koendebruijn.template.user.dto;

import lombok.Data;

@Data
public class AddRoleToUser {
    private String username;
    private String roleName;
}
