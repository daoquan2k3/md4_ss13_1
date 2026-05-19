package re.identityservice.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/products")
public class MockProductController {
    @GetMapping
    public ResponseEntity<List<String>> getMockProducts() {
        return ResponseEntity.ok(List.of("Bánh mì", "Sữa tươi", "Cà phê gói"));
    }

    @PostMapping
    public ResponseEntity<String> createProduct(
            @RequestHeader("X-User-Id") String userId,
            @RequestHeader("X-User-Role") String userRole,
            @RequestBody String productJson) {

        if (!"ADMIN".equals(userRole) && !"ROLE_ADMIN".equals(userRole)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body("Lỗi 403 Forbidden: Bạn không có quyền thực hiện hành động này!");
        }

        return ResponseEntity.ok(String.format("User [%s] với quyền [%s] đã tạo sản phẩm thành công!", userId, userRole));
    }
}
