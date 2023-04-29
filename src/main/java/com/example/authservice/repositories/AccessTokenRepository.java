package com.example.authservice.repositories;

import com.example.authservice.entities.AccessToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface AccessTokenRepository extends JpaRepository<AccessToken, String> {

    Optional<AccessToken> findAccessTokenByToken(String token);

}
