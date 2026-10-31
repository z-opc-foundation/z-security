package com.zifang.z.security.web.api;

import com.zifang.z.security.web.config.SecurityHealthIndicator;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 本域健康检查端点（前缀 {@code /api/security/health}）。
 *
 * @author zifang
 */
@RestController
@RequestMapping("/api/security")
public class SecurityHealthController {

    private final SecurityHealthIndicator healthIndicator;

    public SecurityHealthController(SecurityHealthIndicator healthIndicator) {
        this.healthIndicator = healthIndicator;
    }

    /**
     * 健康检查。
     *
     * @return 健康信息
     */
    @GetMapping("/health")
    public Map<String, Object> health() {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("component", healthIndicator.getComponent());
        body.put("status", healthIndicator.getStatus());
        return body;
    }
}
