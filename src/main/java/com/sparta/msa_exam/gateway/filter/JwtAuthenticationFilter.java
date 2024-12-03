package com.sparta.msa_exam.gateway.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import javax.crypto.SecretKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class JwtAuthenticationFilter implements GlobalFilter {

    @Value("${service.jwt.secret}")
    private String secret;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        if(exchange.getRequest().getURI().getPath().startsWith("/auth")) {
            return chain.filter(exchange);
        }

        try {
            String token = extractToken(exchange);
            Claims claims = getClaims(token);
            exchange.getRequest().mutate().header("X-Member-Id", claims.get("id", Long.class).toString());
            exchange.getRequest().mutate().header("X-Member-Role", claims.get("role", String.class));
            return chain.filter(exchange);
        } catch (Exception e) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }
    }

    private String extractToken(ServerWebExchange exchange) {
        String authHeader = exchange.getRequest().getHeaders().getFirst("Authorization");

        if(authHeader == null || !authHeader.startsWith("Bearer ")) {
            return null;
        }

        return authHeader.substring(7);
    }

    private Claims getClaims(String token) {
        SecretKey secretKey = Keys.hmacShaKeyFor(Decoders.BASE64URL.decode(secret));
        Jws<Claims> claimsJws = Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token);
        return claimsJws.getPayload();
    }
}
