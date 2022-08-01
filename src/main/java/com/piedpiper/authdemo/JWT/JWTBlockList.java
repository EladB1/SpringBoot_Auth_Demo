package com.piedpiper.authdemo.JWT;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;

@Entity
public class JWTBlockList {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long jwtid;

    private String token;

    public JWTBlockList() {}

    public JWTBlockList(Long jwtid, String token) {
        this.jwtid = jwtid;
        this.token = token;
    }

    public JWTBlockList(String token) {
        this.token = token;
    }

    public long getJwtid() {
        return jwtid;
    }

    public void setJwtid(long jwtid) {
        this.jwtid = jwtid;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }
}
