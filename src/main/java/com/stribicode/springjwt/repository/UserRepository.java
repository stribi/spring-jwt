package com.stribicode.springjwt.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.stribicode.springjwt.model.User;

public interface UserRepository extends JpaRepository<User, Long>{
	
	Optional<User> findByUsername(String username);
	Optional<User> findByFullName(String fullName);
	Optional<User> findById(Long id);
	
	Boolean existsByUsername(String username);
	
	
	

}
