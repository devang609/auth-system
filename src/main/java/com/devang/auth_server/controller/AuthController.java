package com.devang.auth_server.controller;

import org.springframework.web.bind.annotation.RestController;

import com.devang.auth_server.models.Users;
import com.devang.auth_server.services.AuthenticationManager;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.time.Duration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseCookie;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;


@RestController
public class AuthController {

    @Autowired
    AuthenticationManager authManager;

    @PostMapping("/register")
    public HttpStatusCode register(@RequestBody Users user) {
        return HttpStatusCode.valueOf(204);
    }

    @PostMapping("/login")
    public HttpStatusCode login(@RequestBody String loginRequestBody) throws JsonMappingException, JsonProcessingException {
        ObjectMapper mapper = new ObjectMapper();
        JsonNode root = mapper.readTree(loginRequestBody);

        Long userId = root.path("userId").asLong();
        String password = root.path("password").asText();

        

        ResponseCookie refreshCookie = ResponseCookie.from("refresh_token", refreshToken)
            .httpOnly(true)
            .secure(true)          
            .sameSite("Strict")
            .path("/auth/refresh")
            .maxAge(Duration.ofDays(7))
            .build();

        return authManager.authenticate(userId, password) ?
                            HttpStatusCode.valueOf(200) : HttpStatusCode.valueOf(401);
    }

    @PostMapping("/logout")
    public String postMethodName(@RequestBody String entity) {
        
        return entity;
    }

    @GetMapping("/.well-known/jwks.json")
    public String getMethodName(@RequestParam String param) {
        return new String();
    }
    
}
