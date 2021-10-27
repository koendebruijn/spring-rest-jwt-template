package com.koendebruijn.template.user;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.koendebruijn.template.user.exception.RoleNotFoundException;
import com.koendebruijn.template.user.exception.UserNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Service
@RequiredArgsConstructor
@Transactional
@Slf4j
public class UserService implements UserDetailsService {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder encoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = getUser(username);
        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
        user.getRoles().forEach(role -> authorities.add(new SimpleGrantedAuthority(role.getName())));

        return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(),authorities);
    }

    public User saveUser(User user) {
        log.info("Adding new user to the database");

        user.setPassword(encoder.encode(user.getPassword()));

        return userRepository.save(user);
    }

    public Role saveRole(Role role) {
        log.info("Adding new role {} to the database", role.getName());
        return roleRepository.save(role);
    }

    public void addRoleToUser(String username, String roleName) {
        log.info("Adding role {} to user {}", roleName, username);

        var user = getUser(username);
        var role = roleRepository.findByName(roleName);

        if (role.isEmpty()) {
            throw new RoleNotFoundException(roleName);
        }

        user.getRoles().add(role.get());
    }

    public User getUser(String username)  {
        log.info("fetch user {}", username);

       var userOptional = userRepository.findByUsername(username);

        if (userOptional.isEmpty()) {
            throw new UserNotFoundException(username);
        }

        return userOptional.get();
    }

    public User updateUser(User user) {
        return userRepository.save(user);
    }

    public List<User> getUsers() {
        log.info("fetching all users");
        return userRepository.findAll();
    }


}
