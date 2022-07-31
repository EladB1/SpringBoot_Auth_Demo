package com.piedpiper.authdemo.configuration;

import com.piedpiper.authdemo.user.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.function.Function;

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
    protected InMemoryUserDetailsManager userDetailsService() {
        Function<String, String> encoder = (password) -> passwordEncoder().encode(password);
        UserDetails user = User
                .withUsername("jimmy.neutron")
                .passwordEncoder(encoder)
                .password("secret")
                .roles("ADMIN")
                .build();
        //System.out.println(user.getPassword()); // will show on app start; should be result of bcrypt hashing
        return new InMemoryUserDetailsManager(user);
    }

    @Bean
    protected SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeRequests().antMatchers("/token**").permitAll()
            .and()
            .authorizeRequests().anyRequest().authenticated().and()
            .csrf().disable()
            .formLogin().disable()
            .httpBasic().disable()
            .addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class)
            .userDetailsService(userDetailsService())
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);


        return http.build();
    }
}
