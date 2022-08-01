package com.piedpiper.authdemo.user;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository("UserRepository")
public interface UserRepository extends CrudRepository<AppUser, String> {
}
