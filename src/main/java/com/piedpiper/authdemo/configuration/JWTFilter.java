package com.piedpiper.authdemo.configuration;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.piedpiper.authdemo.JWTResponseDAO;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class JWTFilter extends OncePerRequestFilter {
    @Autowired
    private JWTUtil jwtUtil;

    public UserDetails fakeGetUser(String username) {
        UserDetails user = User.withUsername(username).password("secret").authorities("ADMIN").build();
        return user;
    }

    private void handleError(HttpServletResponse response, String message) throws IOException {
        response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
        JWTResponseDAO json = new JWTResponseDAO(message, null);
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
            if ( jwt == null || jwt.isEmpty()) {
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
                    UserDetails userDetails = fakeGetUser(username);

                    UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, userDetails.getPassword(), userDetails.getAuthorities());
                    if (SecurityContextHolder.getContext().getAuthentication() == null) {
                        SecurityContextHolder.getContext().setAuthentication(token);
                    }
                }
                catch(JWTVerificationException err) {
                    handleError(response, err.getMessage());
                    return;
                }
            }
        }
        else {
            if (!request.getRequestURI().equals("/token")) {
                // endpoint "/token" is where you get a JWT so none needed; for some reason this filter applies there too
                handleError(response, "Missing or misconfigured Bearer token");
                return;
            }
        }
        chain.doFilter(request, response);
    }
}
