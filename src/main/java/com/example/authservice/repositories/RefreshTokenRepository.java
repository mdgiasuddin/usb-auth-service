package com.example.authservice.repositories;

import com.example.authservice.entities.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, String> {
    Optional<RefreshToken> findRefreshTokenByToken(String token);
}
