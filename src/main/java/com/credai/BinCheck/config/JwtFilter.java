package com.credai.BinCheck.config;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.credai.BinCheck.service.CustomUserDetailsService;
import com.credai.BinCheck.service.JwtService;

import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtFilter extends OncePerRequestFilter {

	private static final Logger logger = LoggerFactory.getLogger(JwtFilter.class);

	@Autowired
	private JwtService jwtService;

	@Autowired
	private CustomUserDetailsService customUserDetailsService;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		String authHeader = request.getHeader("Authorization");
		String token = null;
		String username = null;

		if (authHeader != null && authHeader.startsWith("Bearer ")) {
			token = authHeader.substring(7);
			try {
				username = jwtService.extractUsername(token);
			} catch (ExpiredJwtException e) {
				logger.error("Token has expired: {}", e.getMessage());
				response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
				response.getWriter().write("Token has expired");
				return;
			} catch (Exception e) {
				logger.error("Error retrieving username from token: {}", e.getMessage());
				response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
				response.getWriter().write("Invalid token");
				return;
			}
		}

		if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
			try {
				UserDetails userDetails = customUserDetailsService.loadUserByUsername(username);

				if (jwtService.validateToken(token, userDetails)) {
					logger.info("Token is valid for username: {}", username);
					UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails,
							null, userDetails.getAuthorities());
					authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
					SecurityContextHolder.getContext().setAuthentication(authToken);
				} else {
					logger.warn("Token validation failed for username: {}", username);
					response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
					response.getWriter().write("Invalid token");
					return;

				}
			} catch (Exception e) {
				logger.error("Error loading user details for username: {}", username);
				response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
				response.getWriter().write("Error processing authentication");
				return;
			}

		}

		filterChain.doFilter(request, response);
	}
}