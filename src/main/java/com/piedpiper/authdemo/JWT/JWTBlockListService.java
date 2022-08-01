package com.piedpiper.authdemo.JWT;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
public class JWTBlockListService {

    private JWTBlockListRepository jwtBlockRepo;

    @Autowired
    public JWTBlockListService(JWTBlockListRepository jwtBlockRepo) {
        this.jwtBlockRepo = jwtBlockRepo;
    }

    public List<JWTBlockList> findAll() {
        List<JWTBlockList> blockList = new ArrayList<>();
        Iterable<JWTBlockList> blockedJWTs = jwtBlockRepo.findAll();
        for (JWTBlockList jwt : blockedJWTs) {
            blockList.add(jwt);
        }
        return blockList;
    }

    public JWTBlockList findById(long id) {
        Optional<JWTBlockList> jwt = jwtBlockRepo.findById(id);
        if (jwt.isEmpty())
            return null;
        return jwt.get();
    }

    public JWTBlockList findByToken(String token) {
        Optional<JWTBlockList> jwt = jwtBlockRepo.findByToken(token);
        if (jwt.isEmpty())
            return null;
        return jwt.get();
    }

    public JWTBlockList save(JWTBlockList jwt) {
        return jwtBlockRepo.save(jwt);
    }

    // TODO: Remove expired tokens from DB periodically
}
