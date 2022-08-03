package com.piedpiper.authdemo.controller;

import com.piedpiper.authdemo.JWT.JWTBlockList;
import com.piedpiper.authdemo.JWT.JWTBlockListService;
import com.piedpiper.authdemo.JWT.JWTResponseDTO;
import com.piedpiper.authdemo.JWT.JWTUtil;
import com.piedpiper.authdemo.user.AppUser;
import com.piedpiper.authdemo.user.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;
import java.util.HashMap;
import java.util.Map;

@RestController
@CrossOrigin(origins = {"http://localhost:3000"})
public class AuthController {

    JWTUtil jwtUtil;
    PasswordEncoder passwordEncoder;
    UserService userDetailsService;
    JWTBlockListService blockListService;

    @Autowired
    public AuthController(JWTUtil jwtUtil, PasswordEncoder passwordEncoder, UserService userDetailsService, JWTBlockListService blockListService) {
        this.jwtUtil = jwtUtil;
        this.passwordEncoder = passwordEncoder;
        this.userDetailsService = userDetailsService;
        this.blockListService = blockListService;
    }

    @PostMapping("/signup")
    public ResponseEntity<Map<String, String>> register(@Valid @RequestBody AppUser appUser) {
        Map<String, String> result = new HashMap<>();
        HttpStatus status = HttpStatus.BAD_REQUEST; // bad request by default
        try {
            appUser.setPassword(passwordEncoder.encode(appUser.getPassword())); // store the hash of the password
            AppUser newUser = userDetailsService.save(appUser);
            result.put("Username", newUser.getUsername());
            status = HttpStatus.OK;
            return new ResponseEntity<>(result, status);
        }
        catch (BadCredentialsException err) {
            result.put("Error", err.getMessage());
            return new ResponseEntity<>(result, status);
        }
    }

    @PostMapping("/token")
    public ResponseEntity<JWTResponseDTO> token(@RequestBody AppUser appUser) {
        try {
            UserDetails user = userDetailsService.loadUserByUsername(appUser.getUsername());
            if (!passwordEncoder.matches(appUser.getPassword(), user.getPassword())) {
                throw new BadCredentialsException("Invalid username or password");
            }
            String token = jwtUtil.generateToken(appUser.getUsername());
            JWTResponseDTO response = new JWTResponseDTO(null, token);
            return ResponseEntity.ok().body(response);
        }
        catch(UsernameNotFoundException err) {
            JWTResponseDTO response = new JWTResponseDTO("Invalid username or password", null);
            return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
        }
        catch (AuthenticationException err) {
            //System.out.println(err.getClass() + ": " + err.getMessage());
            JWTResponseDTO response = new JWTResponseDTO(err.getMessage(), null);
            return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logout(@RequestHeader("Authorization") String token) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        //String sessionID = RequestContextHolder.getRequestAttributes().getSessionId();
        String jwt = token.split(" ")[1];
        blockListService.save(new JWTBlockList(jwt));
        auth.setAuthenticated(false);
        SecurityContextHolder.clearContext();
        return ResponseEntity.ok().body("");
    }
}
