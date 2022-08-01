package com.piedpiper.authdemo.JWT;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface JWTBlockListRepository extends CrudRepository<JWTBlockList, Long> {
    Optional<JWTBlockList> findByToken(String token);
}
