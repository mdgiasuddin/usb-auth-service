package com.example.authservice.entities;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.List;

@Builder
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Entity
@Table(name = "refresh_token")
public class RefreshToken {

    @Id
    private String token;

    private LocalDateTime expiration;

    @OneToMany(fetch = FetchType.LAZY, mappedBy = "refreshToken")
    private List<AccessToken> accessTokens;

}
