package com.piedpiper.authdemo.JWT;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.fasterxml.jackson.databind.ObjectMapper;

import com.piedpiper.authdemo.user.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class JWTFilter extends OncePerRequestFilter {

    private JWTUtil jwtUtil;
    private UserService userService;
    private JWTBlockListService blockListService;

    @Autowired
    public JWTFilter(JWTUtil jwtUtil, JWTBlockListService blockListService, UserService userService) {
        this.jwtUtil = jwtUtil;
        this.blockListService = blockListService;
        this.userService = userService;
    }


    private void handleError(HttpServletResponse response, String message) throws IOException {
        response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
        JWTResponseDTO json = new JWTResponseDTO(message, null);
        ObjectMapper mapper = new ObjectMapper();
        String output = mapper.writeValueAsString(json);
        response.setContentType("application/json");
        response.getOutputStream().print(output);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
        String header = request.getHeader("Authorization");
        if (header != null && !header.isEmpty() && header.startsWith("Bearer ")) {
            String jwt = header.split(" ")[1].trim();
            if (jwt.isEmpty()) {
                handleError(response, "Invalid JWT in Bearer Header");
                return;
            }
            else {
                try {
                    String username = jwtUtil.validateTokenAndGetSubject(jwt);
                    if (username == null || username.isEmpty()) {
                        handleError(response, "Token maybe misconfigured; could not find username");
                        return;
                    }
                    if (blockListService.findByToken(jwt) != null) {
                        handleError(response, "Token has been invalidated");
                        return;
                    }
                    UserDetails userDetails = userService.loadUserByUsername(username);

                    UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, userDetails.getPassword(), userDetails.getAuthorities());
                    if (SecurityContextHolder.getContext().getAuthentication() == null) {
                        SecurityContextHolder.getContext().setAuthentication(token);
                    }
                }
                catch(JWTVerificationException | UsernameNotFoundException err) {
                    handleError(response, err.getMessage());
                    return;
                }
            }
        }
        else {
            // use if statement to ignore certain endpoints
            if (!request.getRequestURI().equals("/token") && !request.getRequestURI().equals("/signup")) {
                handleError(response, "Missing or misconfigured Bearer token");
                return;
            }
        }
        chain.doFilter(request, response);
    }
}
