package com.piedpiper.authdemo.error;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@ControllerAdvice(basePackages = "com.piedpiper.authdemo")
public class ErrorHandler extends ResponseEntityExceptionHandler {
    @Override
    public ResponseEntity<Object> handleMethodArgumentNotValid(MethodArgumentNotValidException err, HttpHeaders headers, HttpStatus status, WebRequest request) {
        Map<String, List<String>> errors = new HashMap<>();
        List<String> details;
        for (FieldError fieldError : err.getBindingResult().getFieldErrors()) {
            if (errors.containsKey(fieldError.getField())) {
                details = errors.get(fieldError.getField());
                details.add(fieldError.getDefaultMessage());
            }
            else {
                details = new ArrayList<>();
                details.add(fieldError.getDefaultMessage());
                errors.put(fieldError.getField(), details);
            }
        }
        return ResponseEntity.badRequest().body(errors);
    }
}
