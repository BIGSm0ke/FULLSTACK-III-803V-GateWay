package com.example.gateway_jwr.security;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class JwtUtilTest {

    @Test
    void generateToken_DebeCrearTokenNoVacio() {
        String token = JwtUtil.generateToken("admin@fireforce.com");
        assertNotNull(token);
        assertFalse(token.isBlank());
    }

    @Test
    void validateToken_ConTokenValido_DebeRetornarTrue() {
        String token = JwtUtil.generateToken("usuario@test.com");
        assertTrue(JwtUtil.validateToken(token));
    }

    @Test
    void validateToken_ConTokenInvalido_DebeRetornarFalse() {
        assertFalse(JwtUtil.validateToken("token_invalido"));
    }

    @Test
    void validateToken_ConTokenVacio_DebeRetornarFalse() {
        assertFalse(JwtUtil.validateToken(""));
    }

    @Test
    void extractUsername_DebeRetornarSubject() {
        String email = "test@fireforce.com";
        String token = JwtUtil.generateToken(email);
        assertEquals(email, JwtUtil.extractUsername(token));
    }

    @Test
    void generateToken_DistintosTokens_DebenSerUnicos() {
        String token1 = JwtUtil.generateToken("user1@test.com");
        String token2 = JwtUtil.generateToken("user2@test.com");
        assertNotEquals(token1, token2);
    }
}
