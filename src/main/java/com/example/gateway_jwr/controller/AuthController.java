package com.example.gateway_jwr.controller;

import com.example.gateway_jwr.dto.LoginRequest;
import com.example.gateway_jwr.dto.LoginResponse;
import com.example.gateway_jwr.security.JwtUtil;
import org.springframework.web.bind.annotation.*;

    @RestController
    @RequestMapping("/auth")
    public class AuthController {

        @PostMapping("/login")
        public LoginResponse login(@RequestBody LoginRequest request) {

            if ("admin".equals(request.username) && "1234".equals(request.password)) {
                String token = JwtUtil.generateToken(request.username);
                return new LoginResponse(token);
            }

            throw new RuntimeException("Credenciales inválidas");
        }
    }

