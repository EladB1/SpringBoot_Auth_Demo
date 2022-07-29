package com.piedpiper.authdemo.user;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class UserService implements UserDetailsService {

    private List<AppUser> appUsers = new ArrayList<>();


    public UserService() {
        appUsers.add(new AppUser("jimmy.neutron", "secret"));
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        for (AppUser appUser : appUsers) {
            if (appUser.getUsername().equals(username))
                return new User(appUser.getUsername(), appUser.getPassword(), new ArrayList<>());
        }
        throw new UsernameNotFoundException("Could not find user with username " + username);
    }
}
