package com.example.gateway_jwr.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.URI;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class JwtFilterTest {

    @Mock
    private ServerWebExchange exchange;
    @Mock
    private GatewayFilterChain chain;
    @Mock
    private ServerHttpRequest request;
    @Mock
    private ServerHttpResponse response;
    @Mock
    private HttpHeaders headers;

    private JwtFilter filter;
    private final URI defaultUri = URI.create("/api/reportes");

    @BeforeEach
    void setUp() {
        filter = new JwtFilter();
    }

    @Test
    void filter_OptionsRequest_DebePasarSinValidar() {
        when(exchange.getRequest()).thenReturn(request);
        when(request.getMethod()).thenReturn(HttpMethod.OPTIONS);
        when(request.getURI()).thenReturn(defaultUri);
        when(chain.filter(exchange)).thenReturn(Mono.empty());

        Mono<Void> result = filter.filter(exchange, chain);

        assertNotNull(result);
        verify(chain, times(1)).filter(exchange);
    }

    @Test
    void filter_LoginPath_DebePasarSinValidar() {
        when(exchange.getRequest()).thenReturn(request);
        when(request.getMethod()).thenReturn(HttpMethod.GET);
        when(request.getURI()).thenReturn(URI.create("/api/auth/login"));
        when(chain.filter(exchange)).thenReturn(Mono.empty());

        filter.filter(exchange, chain);

        verify(chain, times(1)).filter(exchange);
    }

    @Test
    void filter_RegisterPath_DebePasarSinValidar() {
        when(exchange.getRequest()).thenReturn(request);
        when(request.getMethod()).thenReturn(HttpMethod.GET);
        when(request.getURI()).thenReturn(URI.create("/api/auth/register"));
        when(chain.filter(exchange)).thenReturn(Mono.empty());

        filter.filter(exchange, chain);

        verify(chain, times(1)).filter(exchange);
    }

    @Test
    void filter_SinAuthHeader_DebeRetornar401() {
        when(exchange.getRequest()).thenReturn(request);
        when(request.getMethod()).thenReturn(HttpMethod.GET);
        when(request.getURI()).thenReturn(defaultUri);
        when(request.getHeaders()).thenReturn(headers);
        when(headers.getFirst(HttpHeaders.AUTHORIZATION)).thenReturn(null);
        when(exchange.getResponse()).thenReturn(response);
        when(response.setComplete()).thenReturn(Mono.empty());

        filter.filter(exchange, chain);

        verify(response).setStatusCode(HttpStatus.UNAUTHORIZED);
        verify(response).setComplete();
        verifyNoInteractions(chain);
    }

    @Test
    void filter_AuthHeaderSinBearer_DebeRetornar401() {
        when(exchange.getRequest()).thenReturn(request);
        when(request.getMethod()).thenReturn(HttpMethod.GET);
        when(request.getURI()).thenReturn(defaultUri);
        when(request.getHeaders()).thenReturn(headers);
        when(headers.getFirst(HttpHeaders.AUTHORIZATION)).thenReturn("Basic token123");
        when(exchange.getResponse()).thenReturn(response);
        when(response.setComplete()).thenReturn(Mono.empty());

        filter.filter(exchange, chain);

        verify(response).setStatusCode(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void filter_TokenInvalido_DebeRetornar401() {
        when(exchange.getRequest()).thenReturn(request);
        when(request.getMethod()).thenReturn(HttpMethod.GET);
        when(request.getURI()).thenReturn(defaultUri);
        when(request.getHeaders()).thenReturn(headers);
        when(headers.getFirst(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer token-invalido");
        when(exchange.getResponse()).thenReturn(response);
        when(response.setComplete()).thenReturn(Mono.empty());

        filter.filter(exchange, chain);

        verify(response).setStatusCode(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void filter_TokenValido_DebePasarYAgregarHeaders() {
        String token = JwtUtil.generateToken("testuser");
        ServerHttpRequest.Builder requestBuilder = mock(ServerHttpRequest.Builder.class);
        ServerHttpRequest mutatedRequest = mock(ServerHttpRequest.class);
        ServerWebExchange.Builder exchangeBuilder = mock(ServerWebExchange.Builder.class);
        ServerWebExchange mutatedExchange = mock(ServerWebExchange.class);

        when(exchange.getRequest()).thenReturn(request);
        when(request.getMethod()).thenReturn(HttpMethod.GET);
        when(request.getURI()).thenReturn(defaultUri);
        when(request.getHeaders()).thenReturn(headers);
        when(headers.getFirst(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer " + token);
        when(request.mutate()).thenReturn(requestBuilder);
        when(requestBuilder.header("X-User-Name", "testuser")).thenReturn(requestBuilder);
        when(requestBuilder.header("X-User-Token", token)).thenReturn(requestBuilder);
        when(requestBuilder.build()).thenReturn(mutatedRequest);
        when(exchange.mutate()).thenReturn(exchangeBuilder);
        when(exchangeBuilder.request(mutatedRequest)).thenReturn(exchangeBuilder);
        when(exchangeBuilder.build()).thenReturn(mutatedExchange);
        when(chain.filter(mutatedExchange)).thenReturn(Mono.empty());

        filter.filter(exchange, chain);

        verify(request).mutate();
        verify(requestBuilder).header("X-User-Name", "testuser");
        verify(requestBuilder).header("X-User-Token", token);
    }
}
