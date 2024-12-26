package com.credai.BinCheck.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Entity
@Table(name="USERB")
@Data
public class User {
	
	@Id
	@GeneratedValue(strategy = GenerationType.AUTO)
	private Long id;

	@Column(unique = true,nullable = false)
	@NotBlank(message = "Username cannot be blank")
	private String username;
	
	@Column(nullable = false)
	@NotBlank(message = "Password cannot be blank")
	private String password;
	
	@Column(nullable = false)
    private String role = "USER";
	
	
	
}
