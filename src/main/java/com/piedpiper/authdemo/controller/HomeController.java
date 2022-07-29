package com.piedpiper.authdemo.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@Controller
public class HomeController {
    private Map<String, LocalDateTime> usersLastAccess = new HashMap<>();

    @GetMapping("/")
    public String getCurrentUser(@AuthenticationPrincipal User user, Model model) {
        String username = "TEst"; //user.getUsername();

        model.addAttribute("username", username);
        model.addAttribute("lastAccess", usersLastAccess.get(username));

        usersLastAccess.put(username, LocalDateTime.now());

        return "home";
    }
}
