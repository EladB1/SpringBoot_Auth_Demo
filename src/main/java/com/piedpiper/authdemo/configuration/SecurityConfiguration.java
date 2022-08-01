package com.piedpiper.authdemo.configuration;

import com.piedpiper.authdemo.user.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


@Configuration
@EnableWebSecurity
public class SecurityConfiguration {
    private BCryptPasswordEncoder encoder;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return encoder;
    }

    @Autowired
    UserService userService;

    @Autowired
    JWTFilter filter;

    public SecurityConfiguration(UserService userService) {
        this.encoder = new BCryptPasswordEncoder();
    }


    @Bean
    protected AuthenticationProvider daoAuthProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder());
        provider.setUserDetailsService(userService);
        return provider;
    }

    @Bean
    protected SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeRequests().antMatchers("/token**").permitAll()
            .and()
            .authorizeRequests().antMatchers("/signup**").permitAll()
            .and()
            .authorizeRequests().anyRequest().authenticated().and()
            .csrf().disable()
            .formLogin().disable()
            .httpBasic().disable()
            .addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class)
            .userDetailsService(userService)
            .authenticationProvider(daoAuthProvider())
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        return http.build();
    }
}
