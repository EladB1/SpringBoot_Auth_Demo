package com.piedpiper.authdemo.controller;

import com.piedpiper.authdemo.configuration.JWTUtil;
import com.piedpiper.authdemo.user.AppUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthController {

    @Autowired
    JWTUtil jwtUtil;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    UserDetailsService userDetailsService;


    @PostMapping("/token")
    public ResponseEntity<String> token(@RequestBody AppUser appUser) {
        try {
            UserDetails user = userDetailsService.loadUserByUsername(appUser.getUsername());
            if (user == null)
                throw new UsernameNotFoundException("Invalid username or password");
            System.out.println(user.getPassword());
            if (!passwordEncoder.matches(appUser.getPassword(), user.getPassword())) {
                throw new BadCredentialsException("Invalid username or password");
            }
            String token = jwtUtil.generateToken(appUser.getUsername());
            return ResponseEntity.ok().body(token);
        }
        catch (AuthenticationException err) {
            return new ResponseEntity<>(err.getMessage(), HttpStatus.BAD_REQUEST);
        }
    }
}
