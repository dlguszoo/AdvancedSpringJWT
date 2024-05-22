package com.example.advancedspringjwt.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.Getter;
import lombok.Setter;

@Entity
@Getter
@Setter
public class RefreshEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;

    private String username; //어떤 유저에 대한 토큰인지. 한 유저가 여러개의 토큰 발급받을 수 있기에 unique 설정은 X

    private String refresh; //유저가 가진 Refresh 토큰

    private String expiration; //토큰이 언제 만료되는지


}
