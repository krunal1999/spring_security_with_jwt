package com.example.krunal.springsecutiyjwt.service;

import com.example.krunal.springsecutiyjwt.controller.AuthenticationRequest;
import com.example.krunal.springsecutiyjwt.controller.AuthenticationResponse;
import com.example.krunal.springsecutiyjwt.controller.RegisterRequest;
import com.example.krunal.springsecutiyjwt.entity.Role;
import com.example.krunal.springsecutiyjwt.entity.User;
import com.example.krunal.springsecutiyjwt.repositary.UserRepositary;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final UserRepositary userRepositary;

    private final PasswordEncoder passwordEncoder;

    private final JwtService jwtService;

    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(RegisterRequest request) {
        User user = User.builder().firstName(request.getFirstname()).lastName(request.getLastName())
                .email(request.getEmail()).password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();

        userRepositary.save(user);

        var jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
        
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {

        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getEmail(),request.getPassword()));
        var user = userRepositary.findByEmail(request.getEmail()).orElseThrow();

        var jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();

    }
}
