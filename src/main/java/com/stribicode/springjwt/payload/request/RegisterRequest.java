package com.stribicode.springjwt.payload.request;

import java.util.Set;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;


public class RegisterRequest {
	
	@NotBlank
	@Size(min = 3, max =  50)
	private String fullName;
	
	@NotBlank
	@Size(max = 120)
	@Email
	private String username;
	
	@NotBlank
	@Size(min = 6, max = 40)
	private String password;
	
	
	private Set<String> role;

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

	public String getFullName() {
		return fullName;
	}

	public void setFullName(String fullName) {
		this.fullName = fullName;
	}

	public Set<String> getRole() {
		return role;
	}

	public void setRole(Set<String> role) {
		this.role = role;
	}
	
	
}
