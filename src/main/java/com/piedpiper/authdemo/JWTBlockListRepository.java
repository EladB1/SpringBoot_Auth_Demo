package com.piedpiper.authdemo;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface JWTBlockListRepository extends CrudRepository<JWTBlockList, Long> {
    public Optional<JWTBlockList> findByToken(String token);
}
