package re.identityservice.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import re.identityservice.config.JwtUtil;
import re.identityservice.dto.request.AuthRequest;
import re.identityservice.dto.response.AuthResponse;
import re.identityservice.entity.Role;
import re.identityservice.entity.User;
import re.identityservice.repository.UserRepository;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;

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

    // Thực hiện logic xác thực thủ công tại tầng Service
    public AuthResponse login(AuthRequest request) {
        // Truy vấn User từ Database thông qua UserRepository
        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new RuntimeException("Tên đăng nhập hoặc mật khẩu không chính xác!"));

        // Sử dụng matches(rawPassword, encodedPassword) để đối soát
        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new RuntimeException("Tên đăng nhập hoặc mật khẩu không chính xác!");
        }

        // Nếu thành công, sử dụng JwtUtil sinh JWT chứa username và role
        String token = jwtUtil.generateToken(user.getUsername(), user.getRole().name());

        return new AuthResponse(token);
    }

    public String generateTestToken(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("Không tìm thấy user với username: " + username));

        String roleName = user.getRole().name();

        return jwtUtil.generateToken(user.getUsername(), roleName);
    }
}
