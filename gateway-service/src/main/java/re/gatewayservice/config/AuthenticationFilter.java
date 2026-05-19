package re.gatewayservice.config;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

@Component
public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {

    @Value("${jwt.secret-key}")
    private String secretKey;

    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    public AuthenticationFilter() {
        super(Config.class);
    }

    public static class Config {
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            String path = request.getURI().getPath();

            if (pathMatcher.match("/identity/api/auth/**", path)) {
                return chain.filter(exchange);
            }

            if (!request.getHeaders().containsHeader(HttpHeaders.AUTHORIZATION)) {
                return onError(exchange, "Thiếu Header Authorization trong yêu cầu!", HttpStatus.UNAUTHORIZED);
            }

            String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return onError(exchange, "Định dạng Token không hợp lệ!", HttpStatus.UNAUTHORIZED);
            }

            String token = authHeader.substring(7);

            try {
                byte[] keyBytes = Decoders.BASE64.decode(secretKey);
                SecretKey key = Keys.hmacShaKeyFor(keyBytes);

                // 1. Giải mã và thu về đối tượng Claims
                Jws<Claims> claimsJws = Jwts.parser()
                        .verifyWith(key)
                        .build()
                        .parseSignedClaims(token);

                Claims claims = claimsJws.getPayload();
                String username = claims.getSubject();
                String role = claims.get("role", String.class);

                // 2. Bảo mật toàn vẹn: Tạo bản sao request mới (mutate) mang Header tùy chỉnh
                ServerHttpRequest mutatedRequest = request.mutate()
                        .header("X-User-Id", username)
                        .header("X-User-Role", role)
                        .build();

                // 3. Đưa request đã mutate vào exchange để chuyển tiếp xuống downstream service
                return chain.filter(exchange.mutate().request(mutatedRequest).build());

            } catch (SignatureException e) {
                return onError(exchange, "Chữ ký Token không hợp lệ!", HttpStatus.UNAUTHORIZED);
            } catch (ExpiredJwtException e) {
                return onError(exchange, "Token đã hết hạn sử dụng!", HttpStatus.UNAUTHORIZED);
            } catch (MalformedJwtException | IllegalArgumentException e) {
                return onError(exchange, "Cấu trúc Token không hợp lệ!", HttpStatus.UNAUTHORIZED);
            } catch (Exception e) {
                return onError(exchange, "Lỗi xác thực Token hệ thống!", HttpStatus.UNAUTHORIZED);
            }
        };
    }

    // SỬA: Thay thế viết trực tiếp package thành class đã import ngắn gọn
    private Mono<Void> onError(ServerWebExchange exchange, String errorMessage, HttpStatus status) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(status);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        String jsonResponseBody = String.format("{\"status\": %d, \"error\": \"%s\", \"message\": \"%s\"}",
                status.value(), status.getReasonPhrase(), errorMessage);

        byte[] bytes = jsonResponseBody.getBytes(StandardCharsets.UTF_8);
        DataBuffer buffer = response.bufferFactory().wrap(bytes);

        return response.writeWith(Mono.just(buffer));
    }
}