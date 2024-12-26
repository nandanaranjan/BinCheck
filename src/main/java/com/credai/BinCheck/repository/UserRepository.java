package com.credai.BinCheck.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.credai.BinCheck.entity.User;

public interface UserRepository extends JpaRepository<User,Long> {
	Optional<User> findByUsername(String username);

}
