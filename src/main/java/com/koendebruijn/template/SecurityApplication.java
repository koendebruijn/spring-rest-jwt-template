package com.koendebruijn.template;

import com.koendebruijn.template.user.Role;
import com.koendebruijn.template.user.User;
import com.koendebruijn.template.user.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
public class SecurityApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecurityApplication.class, args);
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    CommandLineRunner run(UserService userService) {
        return args -> {
            userService.saveRole(new Role(null, "ROLE_USER"));
            userService.saveRole(new Role(null, "ROLE_ADMIN"));

            userService.saveUser(new User(null, "Koen de Bruijn", "admin", "123", new ArrayList<>()));
            userService.saveUser(new User(null, "Koen de Bruijn", "user", "123", new ArrayList<>()));

            userService.addRoleToUser("admin", "ROLE_ADMIN");
            userService.addRoleToUser("admin", "ROLE_USER");
            userService.addRoleToUser("user", "ROLE_USER");
        };
    }
}
