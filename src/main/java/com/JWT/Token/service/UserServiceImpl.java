package com.JWT.Token.service;

import com.JWT.Token.models.Role;
import com.JWT.Token.models.User;
import com.JWT.Token.repositories.RoleRepository;
import com.JWT.Token.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Service
@Slf4j
@RequiredArgsConstructor
public class UserServiceImpl implements UserService, UserDetailsService {

     private final UserRepository userRepository;
     private final RoleRepository roleRepository;
     private final PasswordEncoder passwordEncoder;

    @Override
    public User saveUser(User user) {
        log.info("Saving new user {} to the database", user.getName());
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepository.save(user);
    }

    @Override
    public Role roleUser(Role role) {
        log.info("Saving new role {} to the database", role.getName());
        return roleRepository.save(role);
    }

    @Override
    @Transactional
    public void addRoleToUser(String username, String roleName) {
        log.info("Adding role {} to the user", roleName, username);
        User user = userRepository.findByUsername(username);
        Role role = roleRepository.findByName(roleName);

        user.getRoles().add(role);
    }

    @Override
    public User getUser(String username) {
        log.info("Fetching user {} ", username);
        return userRepository.findByUsername(username);
    }

    @Override
    public List<User> findAll() {
        log.info("Fetching all users {} ");
        return userRepository.findAll();
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username);
        if(user == null) {
            log.error("User not found!");
            throw new UsernameNotFoundException("User not found in database!");
        } else {
            log.info("User found in the database {}", username);
        }
        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
        user.getRoles().forEach(role -> authorities.add(new SimpleGrantedAuthority(role.getName())));
        return new org.springframework.security.core.userdetails.
                User(user.getUsername(), user.getPassword(), authorities);

    }
}
