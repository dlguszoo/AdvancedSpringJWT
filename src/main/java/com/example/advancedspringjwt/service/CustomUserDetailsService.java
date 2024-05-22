package com.example.advancedspringjwt.service;

import com.example.advancedspringjwt.dto.CustomUserDetails;
import com.example.advancedspringjwt.entity.UserEntity;
import com.example.advancedspringjwt.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService {
    private final UserRepository userRepository;

    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserEntity userEntity = userRepository.findByUsername(username);
        if(userEntity != null) {
            return new CustomUserDetails(userEntity);
        }
        return null;
    }
}
