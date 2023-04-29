package com.example.authservice.entities;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Builder
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Entity
@Table(name = "access_token")
public class AccessToken {

    @Id
    private String token;

    @ManyToOne
    private RefreshToken refreshToken;

    private LocalDateTime expiration;
}
