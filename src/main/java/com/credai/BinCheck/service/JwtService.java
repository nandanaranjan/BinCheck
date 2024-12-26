package com.credai.BinCheck.service;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import javax.crypto.SecretKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {
	
	private static final Logger logger = LoggerFactory.getLogger(JwtService.class);

    private static final String secretKey = "xNjpHDq86pH759AutFCB8uoK6ndeDFRR4qUfKzUJ4lw="; 	

	public String generateToken(String username) {
		logger.info("Generating token for username: {}", username);
		Map<String, Object> claims = new HashMap<>();
        try {
		String token =  Jwts.builder()
				.claims()
				.add(claims)
				.subject(username)
				.issuedAt(new Date(System.currentTimeMillis()))
				.expiration(new Date(System.currentTimeMillis() + 30 * 60 * 1000))
				.and()
				.signWith(getKey())
				.compact();
		logger.info("Token generated successfully for username: {}", username);
        return token;
        }catch (Exception e) {
            logger.error("Error while generating token for username: {}", username, e);
            throw new RuntimeException("Failed to generate JWT token", e);
        }

	}

	private SecretKey getKey() {
		try {
			byte[] keyBytes = Decoders.BASE64.decode(secretKey);
			return Keys.hmacShaKeyFor(keyBytes);
		}catch (Exception e) {
            logger.error("Error while decoding Secret key", e);
            throw new RuntimeException("Failed to decode Secret Key", e);
        }
	}

	    public String extractUsername(String token) {
	    	try {
	            return extractClaim(token, Claims::getSubject);
	        } catch (Exception e) {
	            logger.error("Error while extracting username from token", e);
	            throw new RuntimeException("Failed to extract username from token", e);
	        }
	    }

	    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
	    	try {
	            final Claims claims = extractAllClaims(token);
	            return claimsResolver.apply(claims);
	        } catch (Exception e) {
	            logger.error("Error while extracting claims from token", e);
	            throw new RuntimeException("Failed to extract claims from token", e);
	        }
	    }

		private Claims extractAllClaims(String token) {
			try {
				return Jwts.parser()
						.verifyWith(getKey())
						.build()
						.parseSignedClaims(token)
						.getPayload();
			} catch (MalformedJwtException e) {
				logger.error("Invalid JWT token", e);
				throw new RuntimeException("Invalid JWT token", e);
			} catch (Exception e) {
				logger.error("Error while parsing JWT token", e);
				throw new RuntimeException("Failed to parse JWT token", e);
			}
		}
	    
	    public boolean validateToken(String token, UserDetails userDetails) {
	    	logger.info("Validating token for user: {}", userDetails.getUsername());
	    	try {
				final String username = extractUsername(token);
				boolean isValid = username.equals(userDetails.getUsername()) && !isTokenExpired(token);
				if (isValid) {
					logger.info("Token validation successful for user: {}", userDetails.getUsername());
				} else {
					logger.warn("Token validation failed for user: {}", userDetails.getUsername());
				}
				return isValid;
			} catch (Exception e) {
				logger.error("Error during token validation for user: {}", userDetails.getUsername(), e);
				return false;

			}
	    }
	  
	    private boolean isTokenExpired(String token) {
	    	try {
	            return extractExpiration(token).before(new Date());
	        } catch (Exception e) {
	            logger.error("Error while checking token expiration", e);
	            throw new RuntimeException("Failed to check token expiration", e);
	        }
	    }

		private Date extractExpiration(String token) {
			try {
				return extractClaim(token, Claims::getExpiration);
			} catch (Exception e) {
				logger.error("Error while extracting token expiration", e);
				throw new RuntimeException("Failed to extract token expiration", e);
			}
		}
}