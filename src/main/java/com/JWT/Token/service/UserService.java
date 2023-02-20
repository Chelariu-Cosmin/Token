package com.JWT.Token.service;

import com.JWT.Token.models.Role;
import com.JWT.Token.models.User;

import java.util.List;

public interface UserService {

    User saveUser(User user);

    Role roleUser(Role role);

    void addRoleToUser(String username, String roleName);

    User getUser(String username);

    List<User> findAll(); //pagination
}
