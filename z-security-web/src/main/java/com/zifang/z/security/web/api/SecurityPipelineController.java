package com.zifang.z.security.web.api;

import com.zifang.z.audit.core.domain.AuditTraceResult;
import com.zifang.z.audit.core.service.AuditTraceService;
import com.zifang.z.security.core.domain.SecurityPolicy;
import com.zifang.z.security.core.domain.SecurityResult;
import com.zifang.z.security.core.service.SecurityPipeline;
import com.zifang.z.security.core.service.SecurityPolicyRegistry;
import com.zifang.z.watermark.core.domain.WatermarkPayload;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 安全流水线端点（**对外防护入口**）。
 *
 * <p><b>路由前缀</b>：{@code /z-team/api/security/**}。
 *
 * <p><b>业务方怎么用</b>：只报<b>场景码</b>（如 {@code CONTRACT_EXPORT}）+ 内容，
 * 策略由本域统一管（合规口径收口）⇒ 业务方不自己拼脱敏策略。
 *
 * @author zifang
 */
@RestController
@RequestMapping("/z-team/api/security")
public class SecurityPipelineController {

    /** 流水线（可空 ⇒ 未装配）。 */
    private final ObjectProvider<SecurityPipeline> pipelineProvider;
    /** 策略注册表（可空）。 */
    private final ObjectProvider<SecurityPolicyRegistry> registryProvider;
    /** 审计反查服务（可空）。 */
    private final ObjectProvider<AuditTraceService> traceServiceProvider;

    /**
     * 构造。
     *
     * @param pipelineProvider    流水线提供者
     * @param registryProvider    策略注册表提供者
     * @param traceServiceProvider 审计反查服务提供者
     */
    public SecurityPipelineController(ObjectProvider<SecurityPipeline> pipelineProvider,
                                      ObjectProvider<SecurityPolicyRegistry> registryProvider,
                                      ObjectProvider<AuditTraceService> traceServiceProvider) {
        this.pipelineProvider = pipelineProvider;
        this.registryProvider = registryProvider;
        this.traceServiceProvider = traceServiceProvider;
    }

    /**
     * 跑一条安全流水线。
     *
     * @param request 请求体
     * @return 处理结果
     */
    @PostMapping("/process")
    public ResponseEntity<Map<String, Object>> process(@RequestBody ProcessRequest request) {
        SecurityPipeline pipeline = pipelineProvider.getIfAvailable();
        if (pipeline == null) {
            return ResponseEntity.status(503).body(error("安全流水线未装配"));
        }
        SecurityPolicyRegistry registry = registryProvider.getIfAvailable();
        SecurityPolicy policy = registry == null
                ? SecurityPolicy.full("DEFAULT", "DEFAULT")
                : registry.resolve(request.getScene());

        WatermarkPayload payload = null;
        if (request.getOperatorId() != null || request.getTraceId() != null
                || policy.runs(com.zifang.z.security.core.domain.SecurityStage.WATERMARK)) {
            // ★ M2 #22：**追踪码不由这里生成** —— 交给流水线统一定（单一来源）。
            //   这里若自己生成一个，水印里的码与审计台账里的码就不是同一个 ⇒ 溯源必然查不到。
            //   流水线会把最终追踪码回写进 payload ⇒ 响应里的 traceId 与水印里的码一致。
            payload = new WatermarkPayload(request.getOperatorId(), request.getTenantId(),
                    request.getBizNo(), request.getTraceId(),
                    request.getTimestamp() == null ? System.currentTimeMillis() : request.getTimestamp());
        }

        SecurityResult result = pipeline.run(request.getText(), policy, payload, request.getOperatorId());

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("ok", true);
        body.put("policyId", policy.getPolicyId());
        body.put("scene", policy.getScene());
        body.put("traceId", result.getTraceId());
        body.put("result", result.toView());
        // 拦截 ⇒ HTTP 403（业务方据此拒绝出域）；其余 200
        return result.isBlocked()
                ? ResponseEntity.status(403).body(body)
                : ResponseEntity.ok(body);
    }

    /**
     * ★ 按追踪码反查安全事件（**三态**：200 查到 / 404 台账没有 / 503 台账不可用）。
     *
     * <p>这是水印溯源闭环的**查询侧**：拿到泄密内容 ⇒ 提取盲水印里的追踪码
     * ⇒ 调本端点 ⇒ 还原「谁在什么时候把哪份单号导出去的」。
     *
     * @param traceId 追踪码
     * @return 反查结果
     */
    @GetMapping("/trace/{traceId}")
    public ResponseEntity<Map<String, Object>> trace(@PathVariable String traceId) {
        AuditTraceService traceService = traceServiceProvider.getIfAvailable();
        if (traceService == null) {
            return ResponseEntity.status(503).body(error("审计反查服务未装配"));
        }
        AuditTraceResult result = traceService.lookup(traceId);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("ok", !result.isUnavailable());
        body.putAll(result.toView());
        if (result.isUnavailable()) {
            return ResponseEntity.status(503).body(body);
        }
        if (!result.isFound()) {
            return ResponseEntity.status(404).body(body);
        }
        return ResponseEntity.ok(body);
    }

    /**
     * 查策略（看某个场景配了什么）。
     *
     * @param scene 场景码（缺省 ⇒ 兜底策略）
     * @return 策略视图
     */
    @GetMapping("/policies")
    public ResponseEntity<Map<String, Object>> policies(@RequestParam(required = false) String scene) {
        SecurityPolicyRegistry registry = registryProvider.getIfAvailable();
        if (registry == null) {
            return ResponseEntity.status(503).body(error("策略注册表未装配"));
        }
        SecurityPolicy policy = registry.resolve(scene);
        Map<String, Object> view = new LinkedHashMap<>();
        view.put("policyId", policy.getPolicyId());
        view.put("scene", policy.getScene());
        view.put("stages", policy.getStages().stream().map(Enum::name).toList());
        view.put("watermarkType", policy.getWatermarkType() == null
                ? null : policy.getWatermarkType().name());
        view.put("blockThreshold", policy.getBlockThreshold());
        view.put("enabled", policy.isEnabled());
        view.put("remark", policy.getRemark());

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("ok", true);
        body.put("policy", view);
        body.put("scenes", registry.scenes());
        return ResponseEntity.ok(body);
    }

    /** 列出全部已登记场景。 */
    @GetMapping("/scenes")
    public ResponseEntity<Map<String, Object>> scenes() {
        SecurityPolicyRegistry registry = registryProvider.getIfAvailable();
        if (registry == null) {
            return ResponseEntity.status(503).body(error("策略注册表未装配"));
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("ok", true);
        body.put("scenes", registry.scenes());
        return ResponseEntity.ok(body);
    }

    /** 错误体。 */
    private static Map<String, Object> error(String message) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("ok", false);
        body.put("message", message);
        return body;
    }

    /**
     * 处理请求体。
     */
    public static class ProcessRequest {

        /** 待处理文本。 */
        private String text;
        /** 场景码（决定用哪条策略）。 */
        private String scene;
        /** 操作人。 */
        private String operatorId;
        /** 租户。 */
        private String tenantId;
        /** 业务单号。 */
        private String bizNo;
        /** 追踪 ID。 */
        private String traceId;
        /** 时间戳（epoch 毫秒）。 */
        private Long timestamp;

        public String getText() {
            return text;
        }

        public void setText(String text) {
            this.text = text;
        }

        public String getScene() {
            return scene;
        }

        public void setScene(String scene) {
            this.scene = scene;
        }

        public String getOperatorId() {
            return operatorId;
        }

        public void setOperatorId(String operatorId) {
            this.operatorId = operatorId;
        }

        public String getTenantId() {
            return tenantId;
        }

        public void setTenantId(String tenantId) {
            this.tenantId = tenantId;
        }

        public String getBizNo() {
            return bizNo;
        }

        public void setBizNo(String bizNo) {
            this.bizNo = bizNo;
        }

        public String getTraceId() {
            return traceId;
        }

        public void setTraceId(String traceId) {
            this.traceId = traceId;
        }

        public Long getTimestamp() {
            return timestamp;
        }

        public void setTimestamp(Long timestamp) {
            this.timestamp = timestamp;
        }
    }
}
