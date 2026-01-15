package com.example.authserver.dto;

public record RegisterRequest(
        String username,
        String password,
        String phone,
        String email,
        String ordId
) {}

