package com.koendebruijn.template.user;

import javassist.NotFoundException;

import java.util.List;

public interface UserService {
    User saveUser(User user);
    Role saveRole(Role role);
    void addRoleToUser(String username,String roleName) throws NotFoundException;
    User getUser(String username) throws NotFoundException;
    List<User> getUsers();
}
