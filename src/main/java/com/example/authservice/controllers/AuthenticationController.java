package com.example.authservice.controllers;

import com.example.authservice.dtos.AuthenticationRequest;
import com.example.authservice.dtos.AuthenticationResponse;
import com.example.authservice.dtos.RegisterRequest;
import com.example.authservice.services.AuthenticationService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.lang.NonNull;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody RegisterRequest request) {
        authenticationService.register(request);
        return ResponseEntity.ok("User created successfully...");
    }

    @GetMapping("/refresh-token")
    public AuthenticationResponse refreshToken(@RequestParam("refresh_token") String refreshJwt) {
        return authenticationService.refreshToken(refreshJwt);
    }

    @PostMapping("/sign-in")
    public AuthenticationResponse signIn(@RequestBody AuthenticationRequest request) {
        return authenticationService.signIn(request);
    }

    @DeleteMapping("/sign-out")
    public ResponseEntity<String> signOut(@NonNull HttpServletRequest request) {
        authenticationService.signOut(request);
        return ResponseEntity.ok("User logged out successfully...");
    }
}
