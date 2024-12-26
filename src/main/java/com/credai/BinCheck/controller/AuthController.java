package com.credai.BinCheck.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.credai.BinCheck.DTO.LoginRequestDTO;
import com.credai.BinCheck.DTO.LoginResponseDTO;
import com.credai.BinCheck.entity.User;
import com.credai.BinCheck.repository.UserRepository;
import com.credai.BinCheck.service.JwtService;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/auth")
public class AuthController {

	private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

	@Autowired
	private UserRepository userRepository;

	@Autowired
	private PasswordEncoder passwordEncoder;

	@Autowired
	private JwtService jwtService;

	@Autowired
	private AuthenticationManager authenticationManager;

	@PostMapping("/register")
	public String register(@Valid @RequestBody User user) {
		try {
			logger.info("Registering User: {}", user.getUsername());
			user.setPassword(passwordEncoder.encode(user.getPassword()));
			user.setRole("USER");
			userRepository.save(user);
			logger.info("User Registered Successfully: {}", user.getUsername());
			return "User Registered Successfully!";
		} catch (Exception e) {
			logger.error("Error registering user: {}", user.getUsername(), e);
			throw new RuntimeException("Registration failed.Please try again");
		}
	}

	@PostMapping("/login")
	public LoginResponseDTO login(@Valid @RequestBody LoginRequestDTO loginRequest) {
		try {
			logger.info("Logging in for User: {}", loginRequest.getUsername());
		Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

		SecurityContextHolder.getContext().setAuthentication(authentication);

		String jwtToken = jwtService.generateToken(authentication.getName());
		logger.info("Login Successful for User: {}", loginRequest.getUsername());
		return new LoginResponseDTO(jwtToken, "Login Successful");
		}catch (BadCredentialsException e) {
            logger.warn("Invalid credentials for user: {}", loginRequest.getUsername());
            throw new RuntimeException("Invalid username or password.");
        } catch (Exception e) {
            logger.error("Error during login for user: {}", loginRequest.getUsername(), e);
            throw new RuntimeException("Login failed. Please try again.");
        }
	}
	 @ExceptionHandler(RuntimeException.class)
	    public String handleRuntimeException(RuntimeException e) {
	        logger.error("Exception: {}", e.getMessage(), e);
	        return e.getMessage();
	    }
}
