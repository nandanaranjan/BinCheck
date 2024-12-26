package com.credai.BinCheck.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.credai.BinCheck.service.CustomUserDetailsService;

@Configuration
@EnableWebSecurity
public class SecurityConfig  {
	
	private static final Logger logger = LoggerFactory.getLogger(SecurityConfig.class);

	@Autowired
    private  CustomUserDetailsService customUserDetailsService;
	
	@Autowired
	private JwtFilter jwtFilter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    	logger.info("Starting SecurityFilterChain Configuration");
        http.csrf(customizer ->customizer.disable())
            .authorizeHttpRequests(request -> request
            .requestMatchers("/auth/register").permitAll()
            .requestMatchers("/auth/login").permitAll()
            .requestMatchers("/bincheck/**").hasAuthority("USER")
            .anyRequest().authenticated())
            .authenticationProvider(daoAuthenticationProvider())
            .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
            .httpBasic(Customizer.withDefaults());
        logger.info("SecurityFilterChain Configuration Completed");
        return http.build();
    }
    
    @Bean
    public PasswordEncoder passwordEncoder() {
    	logger.debug("Creating BCryptPasswordEncoder Bean");
        return new BCryptPasswordEncoder();
    }
    
    @Bean
	public UserDetailsService userDetailsService() {
    	logger.debug("Creating CustomUserDetailsService Bean");
		return customUserDetailsService;
	}
	
	
	@Bean
	public DaoAuthenticationProvider  daoAuthenticationProvider () {
		logger.debug("Creating DaoAuthenticationProvider Bean");
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
		provider.setUserDetailsService(customUserDetailsService);
        provider.setPasswordEncoder(passwordEncoder());
		return provider;
	}
	
	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception{
		logger.debug("Creating AuthenticationManager Bean");
		return config.getAuthenticationManager();
		
	}
}