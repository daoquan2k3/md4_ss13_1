package re.identityservice.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("/api/products")
public class MockProductController {

    private static final List<String> products = new ArrayList<>(List.of("Màn hình ASUS", "Bàn phím cơ", "Chuột Logitech"));

    @GetMapping
    public ResponseEntity<List<String>> getAllProducts() {
        return ResponseEntity.ok(products);
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

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<String> deleteProduct(@PathVariable int id) {
        if (id >= products.size() || id < 0) {
            return ResponseEntity.badRequest().body("Sản phẩm không tồn tại!");
        }
        String removed = products.remove(id);
        return ResponseEntity.ok("Xóa thành công sản phẩm: " + removed);
    }
}
