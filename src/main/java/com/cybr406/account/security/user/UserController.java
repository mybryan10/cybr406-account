package com.cybr406.account.security.user;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Objects;
import java.util.stream.Collector;
import java.util.stream.Collectors;

@RestController
public class UserController {

    private static final GrantedAuthority userRole = new SimpleGrantedAuthority("ROLE_USER");

    @Autowired
    private UserDetailsManager userDetailsManager;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @GetMapping("/check-user")
    private ResponseEntity<List<String>> checkUser(
            @RequestHeader(value = "x-username", required = true) String username,
            @RequestHeader(value = "x-password", required = true) String password) throws Exception {

        try {
            UserDetails userDetails = userDetailsManager.loadUserByUsername(username);

            if (!passwordEncoder.matches(password, userDetails.getPassword()))
                return new ResponseEntity<>(HttpStatus.BAD_REQUEST);

            if (userDetails.getAuthorities().stream().anyMatch(ga -> !Objects.equals(ga, userRole))) {
                return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
            }

            return new ResponseEntity<>(userDetails.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toList()),
                    HttpStatus.OK);
        } catch (Exception E){
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }
    }

}
