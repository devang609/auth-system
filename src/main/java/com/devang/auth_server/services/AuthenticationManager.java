package com.devang.auth_server.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.devang.auth_server.repos.UserRepository;

@Service
public class AuthenticationManager {
    
    @Autowired
    UserRepository userRepository;

    public boolean authenticate(Long userId, String password) {
        
        String pswdHash = new BCryptPasswordEncoder().encode(password);

        return userRepository.find(userId).getPass_hash().equals(pswdHash);
    }
}
