package com.example.advancedspringjwt.service;

import com.example.advancedspringjwt.dto.JoinDto;
import com.example.advancedspringjwt.entity.UserEntity;
import com.example.advancedspringjwt.repository.UserRepository;
import org.hibernate.mapping.Join;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class JoinService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    public JoinService(UserRepository userRepository, BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.userRepository = userRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    public void joinProcess(JoinDto joinDto) {
        String username = joinDto.getUsername();
        String password = joinDto.getPassword();

        Boolean isExist = userRepository.existsByUsername(username);

        if(isExist) {
            return;
        }

        UserEntity userEntity = new UserEntity();

        userEntity.setUsername(username);
        userEntity.setPassword(bCryptPasswordEncoder.encode(password));
        userEntity.setRole("ROLE_ADMIN");

        userRepository.save(userEntity);
    }
}
