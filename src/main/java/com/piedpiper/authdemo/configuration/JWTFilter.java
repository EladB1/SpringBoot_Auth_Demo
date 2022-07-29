package com.piedpiper.authdemo.configuration;

import com.auth0.jwt.exceptions.JWTVerificationException;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
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

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
        String header = request.getHeader("Authorization");

        if (!header.isEmpty() && header.startsWith("Bearer ")) {
            String jwt = header.split(" ")[1].trim();
            if (jwt.isEmpty()) {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid JWT Token in Bearer Header");
            }
            else {
                try {
                    String username = jwtUtil.validateTokenAndGetSubject(jwt);
                    UserDetails userDetails = fakeGetUser(username);

                    UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, userDetails.getPassword(), userDetails.getAuthorities());
                    System.out.println(username);
                    if (SecurityContextHolder.getContext().getAuthentication() == null) {
                        SecurityContextHolder.getContext().setAuthentication(token);
                    }
                }
                catch(JWTVerificationException err) {
                    System.out.println(err.getMessage());
                    response.sendError(HttpServletResponse.SC_BAD_GATEWAY, "Invalid JWT supplied");
                }
            }
        }
        chain.doFilter(request, response);
    }
}
