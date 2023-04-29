package com.example.authservice.services;

import com.example.authservice.configs.security.JWTService;
import com.example.authservice.dtos.AuthenticationRequest;
import com.example.authservice.dtos.AuthenticationResponse;
import com.example.authservice.dtos.RegisterRequest;
import com.example.authservice.entities.AccessToken;
import com.example.authservice.entities.RefreshToken;
import com.example.authservice.entities.User;
import com.example.authservice.repositories.AccessTokenRepository;
import com.example.authservice.repositories.RefreshTokenRepository;
import com.example.authservice.repositories.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import static com.example.authservice.constants.AppConstant.ACCESS_TOKEN_TIMEOUT_MINUTE;
import static com.example.authservice.constants.AppConstant.REFRESH_TOKEN_TIMEOUT_MINUTE;

@Service
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
public class AuthenticationService {

    private final UserDetailsService userDetailsService;
    private final UserRepository userRepository;
    private final AccessTokenRepository accessTokenRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JWTService jwtService;
    private final AuthenticationManager authenticationManager;
    private final PasswordEncoder passwordEncoder;

    public void register(RegisterRequest request) {
        User user = new User();
        user.setFirstName(request.getFirstName());
        user.setLastName(request.getLastName());
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setRole(request.getRole());

        userRepository.save(user);
    }

    public AuthenticationResponse signIn(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );

        User user = userRepository.findUserByEmail(request.getEmail())
                .orElseThrow(() -> new UsernameNotFoundException("User not found..."));

        String accessJwt = jwtService.generateToken(user, ACCESS_TOKEN_TIMEOUT_MINUTE);
        String refreshJwt = jwtService.generateToken(user, REFRESH_TOKEN_TIMEOUT_MINUTE);

        RefreshToken refreshToken = refreshTokenRepository.saveAndFlush(
                RefreshToken.builder()
                        .token(refreshJwt)
                        .expiration(LocalDateTime.now().plusMinutes(REFRESH_TOKEN_TIMEOUT_MINUTE))
                        .build()
        );

        accessTokenRepository.save(
                AccessToken.builder()
                        .token(accessJwt)
                        .refreshToken(refreshToken)
                        .expiration(LocalDateTime.now().plusMinutes(ACCESS_TOKEN_TIMEOUT_MINUTE))
                        .build()
        );

        return AuthenticationResponse.builder()
                .accessToken(accessJwt)
                .refreshToken(refreshJwt)
                .build();
    }

    public void signOut(HttpServletRequest request) {
        final String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new RuntimeException("Invalid request...");
        }

        final String jwt = authHeader.substring(7);
        Optional<AccessToken> accessToken = accessTokenRepository.findAccessTokenByToken(jwt);
        if (accessToken.isEmpty()) {
            throw new RuntimeException("Token not found...");
        }

        RefreshToken refreshToken = accessToken.get().getRefreshToken();
        accessTokenRepository.deleteAll(refreshToken.getAccessTokens());
        refreshTokenRepository.delete(refreshToken);
    }

    public AuthenticationResponse refreshToken(String refreshJwt) {
        final String username = jwtService.extractUsername(refreshJwt);
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        Optional<RefreshToken> refreshToken = refreshTokenRepository.findRefreshTokenByToken(refreshJwt);

        if (jwtService.isTokenValid(refreshJwt, userDetails) && refreshToken.isPresent()) {
            String accessJwt = jwtService.generateToken(userDetails, ACCESS_TOKEN_TIMEOUT_MINUTE);

            accessTokenRepository.save(
                    AccessToken.builder()
                            .token(accessJwt)
                            .refreshToken(refreshToken.get())
                            .expiration(LocalDateTime.now().plusMinutes(ACCESS_TOKEN_TIMEOUT_MINUTE))
                            .build()
            );

            return AuthenticationResponse.builder()
                    .accessToken(accessJwt)
                    .refreshToken(refreshJwt)
                    .build();
        }

        throw new RuntimeException("New token cannot be generated...");
    }
}
