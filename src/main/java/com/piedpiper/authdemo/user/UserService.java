package com.piedpiper.authdemo.user;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Optional;

@Service
public class UserService implements UserDetailsService {

    private UserRepository userRepository;

    @Autowired
    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<AppUser> appUser =  userRepository.findById(username);
        if (appUser.isEmpty())
            throw new UsernameNotFoundException("Could not find user with username " + username);
        else {
            AppUser user = appUser.get();
            //return new User(user.getUsername(), user.getPassword(), new ArrayList<>());
            return User.withUsername(user.getUsername()).password(user.getPassword()).authorities("USER").build();
        }
    }

    public AppUser save(AppUser user) throws BadCredentialsException {
        String username = user.getUsername();
        Optional<AppUser> appUser = userRepository.findById(username);
        if (!appUser.isEmpty())
            throw new BadCredentialsException("Username '" + username + "' already exists");
        return userRepository.save(user);
    }
}
