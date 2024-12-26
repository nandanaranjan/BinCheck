package com.credai.BinCheck.service;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.credai.BinCheck.entity.User;
import com.credai.BinCheck.repository.UserRepository;

@Service
public class CustomUserDetailsService implements UserDetailsService {

	private static final Logger logger = LoggerFactory.getLogger(CustomUserDetailsService.class);

	@Autowired
	private UserRepository userRepository;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		logger.info("Loading user by username: {}", username);
		User user;
		try {
		user = userRepository.findByUsername(username)
				.orElseThrow(() ->new UsernameNotFoundException("User not found with usernam: "+username));
				
		} catch (Exception e) {
            logger.error("Error occurred while fetching user with username: {}", username, e);
            throw new UsernameNotFoundException("Failed to load user: " + e.getMessage(), e);
        }
		
		logger.info("Successfully loaded user: {}", username);
		UserDetails secUserDetails = org.springframework.security.core.userdetails.User.builder()
				.username(user.getUsername())
				.password(user.getPassword())
				.authorities(List.of(new SimpleGrantedAuthority(user.getRole())))
				.build();
		return secUserDetails;
	}
}
