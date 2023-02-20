package com.JWT.Token;

import com.JWT.Token.models.Role;
import com.JWT.Token.models.User;
import com.JWT.Token.service.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;


import java.util.ArrayList;

@SpringBootApplication
public class TokenApplication {

	public static void main(String[] args) {
		SpringApplication.run(TokenApplication.class, args);
	}

	@Bean
	public BCryptPasswordEncoder passwordEncoder(){
		return new BCryptPasswordEncoder ();
	}

	@Bean
	CommandLineRunner run(UserService userService) {
		return args -> {
			userService.roleUser(new Role(null, "ROLE_USER"));
			userService.roleUser(new Role(null, "ROLE_MANAGER"));
			userService.roleUser(new Role(null, "ROLE_ADMIN"));
			userService.roleUser(new Role(null, "ROLE_GUEST"));

			userService.saveUser(new User(null, "Chelariu Andei", "admin", "1234", new ArrayList<>()));
			userService.saveUser(new User(null, "Chelariu Andei", "user", "12", new ArrayList<>()));

			userService.addRoleToUser("admin", "ROLE_ADMIN");
			userService.addRoleToUser("user", "ROLE_USER");
		};
	}


}
