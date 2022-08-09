package com.piedpiper.authdemo.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;

import com.piedpiper.authdemo.user.UserService;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@Controller
@CrossOrigin(origins = {"http://localhost:3000"}, allowCredentials = "true")
public class HomeController {


    private UserService userService;
    private Map<String, LocalDateTime> usersLastAccess;

    @Autowired
    public HomeController(UserService userService) {
        this.userService = userService;
        this.usersLastAccess = new HashMap<>();
    }

    @GetMapping("/")
    public String getCurrentUser(@AuthenticationPrincipal(expression = "@userService.loadUserByUsername(#this)") User user, Model model) {
        String username = user.getUsername();

        model.addAttribute("username", username);
        model.addAttribute("lastAccess", usersLastAccess.get(username));

        usersLastAccess.put(username, LocalDateTime.now());

        return "home";
    }
}
