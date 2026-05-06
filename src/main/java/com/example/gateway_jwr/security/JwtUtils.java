package com.example.gateway_jwr.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.function.Function;

@Component
public class JwtUtils {

    // 1. CLAVE ESTÁTICA: Debe ser idéntica en el microservicio de Usuarios y el Gateway
    // (Debe tener al menos 32 caracteres para HS256)
    private final String SECRET_KEY_STRING = "1a530a4a67486092fcaf4df43fa9bf28359229408f7f488743936ddc8b4a4bcb";
    
    private final Key key = Keys.hmacShaKeyFor(SECRET_KEY_STRING.getBytes());
    
    private final int jwtExpirationMs = 86400000; // 24 horas

    // --- 1. GENERAR TOKEN ---
    public String generateToken(String email) {
        return Jwts.builder()
                .setSubject(email)
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
                .signWith(key)
                .compact();
    }

    // --- 2. EXTRAER USERNAME/EMAIL ---
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    // --- 3. VALIDAR TOKEN (COMPLETO CON EMAIL) ---
    public boolean isTokenValid(String token, String email) {
        final String username = extractUsername(token);
        return (username.equals(email) && !isTokenExpired(token));
    }

    // --- 4. NUEVO: VALIDAR TOKEN SOLO (PARA EL GATEWAY) ---
    public boolean isTokenValid(String token) {
        try {
            // Si el token está mal formado, la firma no coincide o expiró, 
            // la librería lanzará una excepción automáticamente.
            // Si pasa esta línea sin errores, es que es válido.
            return !isTokenExpired(token);
        } catch (Exception e) {
            // Capturamos cualquier error (ej. ExpiredJwtException, SignatureException)
            System.out.println("Error validando el token: " + e.getMessage());
            return false;
        }
    }

    // --- MÉTODOS DE APOYO (Privados) ---
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}