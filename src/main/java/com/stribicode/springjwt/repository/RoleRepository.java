package com.stribicode.springjwt.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.stribicode.springjwt.model.ERole;
import com.stribicode.springjwt.model.Role;

@Repository
public interface RoleRepository extends JpaRepository<Role, Integer> {
	
	Optional<Role> findByName(ERole name);
	

}
