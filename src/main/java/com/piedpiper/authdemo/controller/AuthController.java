package com.piedpiper.authdemo.controller;

import com.piedpiper.authdemo.JWT.JWTBlockList;
import com.piedpiper.authdemo.JWT.JWTBlockListService;
import com.piedpiper.authdemo.JWT.JWTResponseDTO;
import com.piedpiper.authdemo.JWT.JWTUtil;
import com.piedpiper.authdemo.user.AppUser;
import com.piedpiper.authdemo.user.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import java.util.HashMap;
import java.util.Map;

@RestController
@CrossOrigin(origins = {"http://localhost:3000"}, allowCredentials = "true")
public class AuthController {

    JWTUtil jwtUtil;
    PasswordEncoder passwordEncoder;
    UserService userDetailsService;
    JWTBlockListService blockListService;

    @Value("${jwt.maxage.seconds}")
    private int sessionExpiration;

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
    public ResponseEntity<JWTResponseDTO> token(@RequestBody AppUser appUser, HttpServletResponse response) {
        try {
            UserDetails user = userDetailsService.loadUserByUsername(appUser.getUsername());
            if (!passwordEncoder.matches(appUser.getPassword(), user.getPassword())) {
                throw new BadCredentialsException("Invalid username or password");
            }
            String token = jwtUtil.generateToken(appUser.getUsername());
            JWTResponseDTO jwtresponse = new JWTResponseDTO(null, token);
            Cookie cookie = new Cookie("Token", token);
            cookie.setMaxAge(sessionExpiration);
            cookie.setHttpOnly(true);
            cookie.setSecure(false);
            response.addCookie(cookie);
            return ResponseEntity.ok().body(jwtresponse);
        }
        catch(UsernameNotFoundException err) {
            JWTResponseDTO jwtresponse = new JWTResponseDTO("Invalid username or password", null);
            return new ResponseEntity<>(jwtresponse, HttpStatus.BAD_REQUEST);
        }
        catch (AuthenticationException err) {
            JWTResponseDTO jwtresponse = new JWTResponseDTO(err.getMessage(), null);
            return new ResponseEntity<>(jwtresponse, HttpStatus.BAD_REQUEST);
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logout(@CookieValue("Token") String token) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        blockListService.save(new JWTBlockList(token));
        auth.setAuthenticated(false);
        SecurityContextHolder.clearContext();
        return ResponseEntity.ok().body("");
    }
}
