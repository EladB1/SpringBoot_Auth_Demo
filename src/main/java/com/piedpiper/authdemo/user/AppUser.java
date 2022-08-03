package com.piedpiper.authdemo.user;

import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;

@Entity
@Table(name = "users")
public class AppUser {

    @Id
    @Size(min = 5, max = 20, message = "Username must be between 5 and 20 characters in length")
    @Pattern(regexp = "^[A-Za-z][A-Za-z0-9-_@]+$", message = "Username must start with a letter and can contain letters, numbers, '-', '_', and '@'")
    private String username;

    @Size(min = 6, max = 60, message = "Password must be between 6 and 60 characters in length") // needs to be 60 since password is hashed
    @Pattern(regexp = ".*[A-Z].*", message = "Password must contain at least one uppercase letter")
    @Pattern(regexp = ".*[a-z].*", message = "Password must contain at least one lowercase letter")
    @Pattern(regexp = ".*[0-9].*", message = "Password must contain at least one number")
    @Pattern(regexp = ".*[&*^-_@!?%#$+=,.|;:~`].*", message = "Password must contain at least special character")
    private String password;

    public AppUser() {}

    public AppUser(String username, String password) {
        this.username = username;
        this.password = password;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
