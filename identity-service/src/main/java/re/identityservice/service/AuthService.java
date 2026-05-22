package re.identityservice.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import re.identityservice.config.JwtUtils;
import re.identityservice.dto.request.AuthRequest;
import re.identityservice.dto.request.TokenRefreshRequest;
import re.identityservice.dto.response.JwtResponse;
import re.identityservice.entity.RefreshToken;
import re.identityservice.entity.Role;
import re.identityservice.entity.User;
import re.identityservice.repository.RefreshTokenRepository;
import re.identityservice.repository.UserRepository;

import java.util.Date;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenService refreshTokenService;
    private final StringRedisTemplate redisTemplate;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtUtils jwtUtils;

    public String register(AuthRequest request) {
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new RuntimeException("Tên đăng nhập đã tồn tại!");
        }

        User newUser = new User();
        newUser.setUsername(request.getUsername());
        newUser.setPassword(passwordEncoder.encode(request.getPassword()));
        newUser.setRole(Role.ROLE_USER); // Mặc định là USER

        userRepository.save(newUser);
        return "Đăng ký thành công!";
    }

    public JwtResponse login(AuthRequest request) {
        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new RuntimeException("Tên đăng nhập hoặc mật khẩu không chính xác!"));

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new RuntimeException("Tên đăng nhập hoặc mật khẩu không chính xác!");
        }

        String accessToken = jwtUtils.generateAccessToken(user);

        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user.getId());

        return new JwtResponse(accessToken, refreshToken.getToken());
    }

    @Transactional
    public JwtResponse refreshToken(TokenRefreshRequest request) {
        String requestToken = request.getRefreshToken();

        RefreshToken tokenFromDb = refreshTokenRepository.findByToken(requestToken)
                .orElseThrow(() -> new RuntimeException("Refresh token không tồn tại trên hệ thống!"));

        refreshTokenService.verifyExpiration(tokenFromDb);

        User user = tokenFromDb.getUser();

        refreshTokenRepository.delete(tokenFromDb);

        String newAccessToken = jwtUtils.generateAccessToken(user);

        RefreshToken newRefreshToken = refreshTokenService.createRefreshToken(user.getId());

        return new JwtResponse(newAccessToken, newRefreshToken.getToken());
    }

    @Transactional
    public void logout(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new RuntimeException("Token đăng xuất không hợp lệ!");
        }

        String token = authHeader.substring(7);
        Claims claims = Jwts.parser()
                .setSigningKey(getSignKey())
                .build()
                .parseClaimsJws(token)
                .getBody();

        String jti = claims.getId();
        Date expiration = claims.getExpiration();
        String username = claims.getSubject();

        long currentTimeMillis = System.currentTimeMillis();
        long ttlMillis = expiration.getTime() - currentTimeMillis;

        if (ttlMillis > 0) {
            String redisKey = "blacklist:" + jti;
            redisTemplate.opsForValue().set(redisKey, "revoked", ttlMillis, TimeUnit.MILLISECONDS);
        }

        userRepository.findByUsername(username).ifPresent(user -> {
            refreshTokenRepository.deleteByUser(user);
        });
    }
}
