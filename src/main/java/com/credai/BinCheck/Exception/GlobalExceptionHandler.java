package com.credai.BinCheck.Exception;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<String> handleValidationExceptions(MethodArgumentNotValidException ex) {
        String errorMessage = ex.getBindingResult()
                                .getFieldErrors()
                                .stream()
                                .map(fieldError -> fieldError.getField() + ": " + fieldError.getDefaultMessage())
                                .findFirst()
                                .orElse("Validation error");
        return ResponseEntity.badRequest().body(errorMessage);
    }
}

