package com.example.gateway_jwr.security;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class JwtFilter extends AbstractGatewayFilterFactory<JwtFilter.Config> {

    private final JwtUtils jwtUtil;

    // Inyección de tu clase utilitaria JwtUtil
    public JwtFilter(JwtUtils jwtUtil) {
        super(Config.class);
        this.jwtUtil = jwtUtil;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            
            // 1. Comprobar si la petición trae la cabecera 'Authorization'
            if (!exchange.getRequest().getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                return onError(exchange, "Acceso denegado: Falta cabecera de Autorización", HttpStatus.UNAUTHORIZED);
            }

            // 2. Extraer el contenido de la cabecera
            String authHeader = exchange.getRequest().getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
            
            // 3. Comprobar que el formato sea correcto (empieza con "Bearer ")
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                
                // Extraer solo el string del token
                String token = authHeader.substring(7);
                
                try {
                    // 4. Delegar la validación matemática a JwtUtil
                    jwtUtil.isTokenValid(token); 
                    
                } catch (Exception e) {
                    // Si el token expiró, la clave secreta no coincide o está mal formado
                    System.out.println("Gateway rechazó el token: " + e.getMessage());
                    return onError(exchange, "Acceso denegado: Token inválido o expirado", HttpStatus.UNAUTHORIZED);
                }
            } else {
                return onError(exchange, "Acceso denegado: Formato de token incorrecto", HttpStatus.UNAUTHORIZED);
            }

            // 5. Si todo está correcto, permite que la petición continúe hacia el microservicio
            return chain.filter(exchange);
        };
    }

    // Método auxiliar reactivo para detener la petición y devolver un código HTTP
    private Mono<Void> onError(ServerWebExchange exchange, String mensajeLog, HttpStatus httpStatus) {
        // Imprime en la consola del Gateway el motivo del bloqueo para facilitar el desarrollo
        System.err.println("[Seguridad Gateway] " + mensajeLog);
        
        exchange.getResponse().setStatusCode(httpStatus);
        return exchange.getResponse().setComplete();
    }

    // Clase estática requerida por AbstractGatewayFilterFactory
    public static class Config {
        // Vacío, a menos que necesites parámetros configurables desde el application.yaml
    }
}