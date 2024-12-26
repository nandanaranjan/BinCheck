package com.credai.BinCheck.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestTemplate;

@RestController
@RequestMapping("/bincheck")
public class BinController {
	
	private static final Logger logger = LoggerFactory.getLogger(BinController.class);
	
	private static final String HEADER_API_KEY = "X-RapidAPI-Key";
    private static final String HEADER_API_HOST = "X-RapidAPI-Host";
    private static final String HEADER_CONTENT_TYPE = "Content-Type";
    private static final String HEADER_CONTENT_TYPE_VALUE = "application/json";
    private static final String HEADER_API_HOST_VALUE = "bin-ip-checker.p.rapidapi.com";

    private  RestTemplate restTemplate = new RestTemplate();
    
    @Value("${bincheck.api.url}")
    private String apiUrl;

    @Value("${bincheck.api.key}")
    private String apiKey;

    @GetMapping("/{bin}")
    public Object getBinDetails(@PathVariable String bin) {
    	logger.info("Received request to fetch BIN details for: {}", bin);
       
    	if (bin == null || bin.trim().isEmpty()) {
            logger.error("Invalid BIN: {}", bin);
            return "BIN must not be null or empty";
        }
    	
    	String url = apiUrl + "?bin=" + bin;
    	logger.debug("Bin URL: {}", url);
        
        HttpHeaders headers = new HttpHeaders();
        headers.set(HEADER_API_KEY, apiKey); 
        headers.set(HEADER_API_HOST, HEADER_API_HOST_VALUE);
        headers.set(HEADER_CONTENT_TYPE, HEADER_CONTENT_TYPE_VALUE);
       
        String requestBody = "{\"bin\":\"" + bin + "\"}";
        HttpEntity<String> entity = new HttpEntity<>(requestBody,headers);
        
        try {
            logger.debug("Sending request to API..");
            ResponseEntity<Object> response = restTemplate.exchange(url, HttpMethod.POST, entity, Object.class);
            logger.info("Received response from API for BIN: {}", bin);
            return response.getBody();
        } catch (HttpClientErrorException e) {
            logger.error("Client error while fetching BIN details for {}: {}", bin, e.getMessage(), e);
            return "Client error occurred: " + e.getMessage();
        } catch (HttpServerErrorException e) {
            logger.error("Server error while fetching BIN details for {}: {}", bin, e.getMessage(), e);
            return "Server error occurred: " + e.getMessage();
        } catch (Exception e) {
            logger.error("Unexpected error while fetching BIN details for {}: {}", bin, e.getMessage(), e);
            return "An unexpected error occurred: " + e.getMessage();
        }
    }
}
