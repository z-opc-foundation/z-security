package com.zifang.z.security.web.api;

import com.zifang.z.security.core.domain.PolicyRevision;
import com.zifang.z.security.core.domain.SecurityPolicy;
import com.zifang.z.security.core.domain.SecurityStage;
import com.zifang.z.security.core.service.PolicyLedgerService;
import com.zifang.z.security.core.service.SecurityPolicyRegistry;
import com.zifang.z.watermark.core.domain.WatermarkType;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 策略台账管理端点（**改策略不用发版**）。
 *
 * <p><b>路由前缀</b>：{@code /z-team/api/security/policy/**}。
 *
 * <p><b>★ 三条硬约束</b>：
 * <ol>
 *   <li><b>操作人与变更原因必填</b> —— 没有这两个字段的台账答不出「谁改的、为什么改」
 *       ⇒ 内审必挂 ⇒ 服务端直接拒绝，不靠调用方自觉；</li>
 *   <li><b>发布 = 新版本</b>，不是 UPDATE 覆盖 ⇒ 历史不可变；</li>
 *   <li><b>热改是原子替换</b> ⇒ 不会出现「改到一半的空注册表」把拦截阈值掉下去。</li>
 * </ol>
 *
 * @author zifang
 */
@RestController
@RequestMapping("/z-team/api/security/policy")
public class SecurityPolicyAdminController {

    /** 台账服务（可空 ⇒ 未装配数据源）。 */
    private final ObjectProvider<PolicyLedgerService> ledgerProvider;
    /** 策略注册表（可空）。 */
    private final ObjectProvider<SecurityPolicyRegistry> registryProvider;

    /**
     * 构造。
     *
     * @param ledgerProvider   台账服务提供者
     * @param registryProvider 注册表提供者
     */
    public SecurityPolicyAdminController(ObjectProvider<PolicyLedgerService> ledgerProvider,
                                         ObjectProvider<SecurityPolicyRegistry> registryProvider) {
        this.ledgerProvider = ledgerProvider;
        this.registryProvider = registryProvider;
    }

    /**
     * 发布一版策略（**新版本 + 取代旧版 + 热改生效**）。
     *
     * @param request 发布请求
     * @return 发布结果
     */
    @PostMapping("/publish")
    public ResponseEntity<Map<String, Object>> publish(@RequestBody PublishRequest request) {
        PolicyLedgerService ledger = ledgerProvider.getIfAvailable();
        if (ledger == null) {
            return ResponseEntity.status(503).body(error("策略台账未装配"));
        }
        if (request == null) {
            return ResponseEntity.status(400).body(error("请求体为空"));
        }
        SecurityPolicy policy = request.toPolicy();
        if (policy == null) {
            return ResponseEntity.status(400).body(error("策略内容非法"));
        }
        PolicyLedgerService.PublishResult result =
                ledger.publish(policy, request.getOperatorId(), request.getChangeReason());
        if (!result.isOk()) {
            Map<String, Object> body = error(result.getMessage());
            body.put("ok", false);
            return ResponseEntity.status(400).body(body);
        }
        // ★ 发布成功后立刻热改生效（原子替换）
        boolean applied = refreshRegistry(ledger);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("ok", true);
        body.put("message", result.getMessage());
        body.put("revision", PolicyLedgerService.toViews(List.of(result.getRevision())));
        body.put("applied", applied);
        return ResponseEntity.ok(body);
    }

    /**
     * 回滚到某个历史版本（**以新版本号重新发布老内容**）。
     *
     * @param policyId 策略 ID
     * @param revision 版本号
     * @param operator 操作人
     * @param reason   回滚原因
     * @return 回滚结果
     */
    @PostMapping("/rollback")
    public ResponseEntity<Map<String, Object>> rollback(
            @RequestParam String policyId,
            @RequestParam int revision,
            @RequestParam(required = false) String operator,
            @RequestParam(required = false) String reason) {
        PolicyLedgerService ledger = ledgerProvider.getIfAvailable();
        if (ledger == null) {
            return ResponseEntity.status(503).body(error("策略台账未装配"));
        }
        PolicyLedgerService.PublishResult result =
                ledger.rollback(policyId, revision, operator, reason);
        if (!result.isOk()) {
            Map<String, Object> body = error(result.getMessage());
            body.put("ok", false);
            return ResponseEntity.status(400).body(body);
        }
        boolean applied = refreshRegistry(ledger);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("ok", true);
        body.put("message", result.getMessage());
        body.put("revision", PolicyLedgerService.toViews(List.of(result.getRevision())));
        body.put("applied", applied);
        return ResponseEntity.ok(body);
    }

    /**
     * 停用某场景（**该场景不再有生效策略 ⇒ 走兜底**）。
     *
     * @param policyId 策略 ID
     * @param operator 操作人
     * @param reason   停用原因
     * @return 结果
     */
    @PostMapping("/disable")
    public ResponseEntity<Map<String, Object>> disable(
            @RequestParam String policyId,
            @RequestParam(required = false) String operator,
            @RequestParam(required = false) String reason) {
        PolicyLedgerService ledger = ledgerProvider.getIfAvailable();
        if (ledger == null) {
            return ResponseEntity.status(503).body(error("策略台账未装配"));
        }
        boolean ok = ledger.disable(policyId, operator, reason);
        if (!ok) {
            Map<String, Object> body = error("停用失败（策略不存在或操作人为空）");
            body.put("ok", false);
            return ResponseEntity.status(400).body(body);
        }
        boolean applied = refreshRegistry(ledger);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("ok", true);
        body.put("applied", applied);
        return ResponseEntity.ok(body);
    }

    /**
     * 台账全量查询（**所有场景的所有版本**）。
     *
     * @param policyId 策略 ID（可空 ⇒ 全部）
     * @return 台账视图
     */
    @GetMapping("/ledger")
    public ResponseEntity<Map<String, Object>> ledger(
            @RequestParam(required = false) String policyId) {
        PolicyLedgerService ledger = ledgerProvider.getIfAvailable();
        if (ledger == null) {
            return ResponseEntity.status(503).body(error("策略台账未装配"));
        }
        List<PolicyRevision> revisions = (policyId == null || policyId.isEmpty())
                ? ledger.allRevisions()
                : ledger.history(policyId);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("ok", true);
        body.put("total", revisions.size());
        body.put("revisions", PolicyLedgerService.toViews(revisions));
        return ResponseEntity.ok(body);
    }

    /**
     * 当前生效的策略视图（**场景 → 策略**）。
     *
     * @return 生效策略视图
     */
    @GetMapping("/published")
    public ResponseEntity<Map<String, Object>> published() {
        PolicyLedgerService ledger = ledgerProvider.getIfAvailable();
        if (ledger == null) {
            return ResponseEntity.status(503).body(error("策略台账未装配"));
        }
        Map<String, SecurityPolicy> view = ledger.publishedView();
        List<Map<String, Object>> list = new ArrayList<>();
        for (SecurityPolicy p : view.values()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("policyId", p.getPolicyId());
            m.put("scene", p.getScene());
            m.put("stages", p.getStages().stream().map(Enum::name).toList());
            m.put("watermarkType", p.getWatermarkType() == null
                    ? null : p.getWatermarkType().name());
            m.put("blockThreshold", p.getBlockThreshold());
            m.put("enabled", p.isEnabled());
            list.add(m);
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("ok", true);
        body.put("total", list.size());
        body.put("policies", list);
        return ResponseEntity.ok(body);
    }

    /**
     * 热改刷新（**把台账的生效策略刷进注册表**）。
     *
     * <p>也可以不调这个端点 —— 发布 / 回滚 / 停用后已自动刷新。
     * 单独暴露是为了「改了库但没发版」时手动兜一把。
     *
     * @return 刷新结果
     */
    @PostMapping("/refresh")
    public ResponseEntity<Map<String, Object>> refresh() {
        PolicyLedgerService ledger = ledgerProvider.getIfAvailable();
        if (ledger == null) {
            return ResponseEntity.status(503).body(error("策略台账未装配"));
        }
        boolean applied = refreshRegistry(ledger);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("ok", applied);
        body.put("applied", applied);
        return applied ? ResponseEntity.ok(body) : ResponseEntity.status(500).body(body);
    }

    /**
     * 把台账的生效策略**原子替换**进注册表。
     *
     * <p>★ **台账读不出任何生效策略时不做替换** —— 否则注册表被清空
     * ⇒ 全部场景降级到 DEFAULT 兜底 ⇒ 拦截阈值掉到 L4 ⇒ 敏感数据可能出域。
     *
     * @param ledger 台账服务
     * @return 是否成功
     */
    private boolean refreshRegistry(PolicyLedgerService ledger) {
        SecurityPolicyRegistry registry = registryProvider.getIfAvailable();
        if (registry == null) {
            return false;
        }
        try {
            java.util.Collection<SecurityPolicy> effective = ledger.publishedView().values();
            if (effective == null || effective.isEmpty()) {
                System.err.println("[z-security] 台账无生效策略，保留现有注册表（不替换）");
                return false;
            }
            // ★ 原子替换：先在本地构造全量，再一次性换引用
            registry.replaceAll(new ArrayList<>(effective));
            return true;
        } catch (RuntimeException e) {
            System.err.println("[z-security] 热改策略失败：" + e.getMessage());
            return false;
        }
    }

    /** 错误体。 */
    private static Map<String, Object> error(String message) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("ok", false);
        body.put("message", message);
        return body;
    }

    /**
     * 发布请求体。
     */
    public static class PublishRequest {

        /** 策略 ID。 */
        private String policyId;
        /** 场景码。 */
        private String scene;
        /** 阶段序列。 */
        private List<String> stages;
        /** 水印类型。 */
        private String watermarkType;
        /** 拦截阈值（空 ⇒ 不拦）。 */
        private String blockThreshold;
        /** 脱敏策略集 ID。 */
        private String maskPolicySetId;
        /** 是否启用。 */
        private Boolean enabled;
        /** 备注。 */
        private String remark;
        /** 操作人（**必填**）。 */
        private String operatorId;
        /** 变更原因（**必填**）。 */
        private String changeReason;

        /**
         * 转成运行时策略（**阶段解析失败 ⇒ 返回 {@code null}**）。
         *
         * @return 策略；非法返回 {@code null}
         */
        public SecurityPolicy toPolicy() {
            if (policyId == null || policyId.trim().isEmpty()
                    || scene == null || scene.trim().isEmpty()) {
                return null;
            }
            SecurityPolicy p = new SecurityPolicy(policyId.trim(), scene.trim());
            List<SecurityStage> parsed = new ArrayList<>();
            if (stages != null) {
                for (String s : stages) {
                    SecurityStage stage = SecurityStage.fromCode(s);
                    if (stage == null) {
                        // ⚠ 未知阶段 ⇒ 整条策略不生效（不静默丢）
                        return null;
                    }
                    parsed.add(stage);
                }
            }
            p.setStages(parsed);
            WatermarkType wt = WatermarkType.fromCode(watermarkType);
            p.setWatermarkType(wt == null ? WatermarkType.VISIBLE_TEXT : wt);
            p.setBlockThreshold(blockThreshold);
            p.setMaskPolicySetId(maskPolicySetId);
            p.setEnabled(enabled == null || enabled);
            p.setRemark(remark);
            return p;
        }

        public String getPolicyId() {
            return policyId;
        }

        public void setPolicyId(String policyId) {
            this.policyId = policyId;
        }

        public String getScene() {
            return scene;
        }

        public void setScene(String scene) {
            this.scene = scene;
        }

        public List<String> getStages() {
            return stages;
        }

        public void setStages(List<String> stages) {
            this.stages = stages;
        }

        public String getWatermarkType() {
            return watermarkType;
        }

        public void setWatermarkType(String watermarkType) {
            this.watermarkType = watermarkType;
        }

        public String getBlockThreshold() {
            return blockThreshold;
        }

        public void setBlockThreshold(String blockThreshold) {
            this.blockThreshold = blockThreshold;
        }

        public String getMaskPolicySetId() {
            return maskPolicySetId;
        }

        public void setMaskPolicySetId(String maskPolicySetId) {
            this.maskPolicySetId = maskPolicySetId;
        }

        public Boolean getEnabled() {
            return enabled;
        }

        public void setEnabled(Boolean enabled) {
            this.enabled = enabled;
        }

        public String getRemark() {
            return remark;
        }

        public void setRemark(String remark) {
            this.remark = remark;
        }

        public String getOperatorId() {
            return operatorId;
        }

        public void setOperatorId(String operatorId) {
            this.operatorId = operatorId;
        }

        public String getChangeReason() {
            return changeReason;
        }

        public void setChangeReason(String changeReason) {
            this.changeReason = changeReason;
        }
    }
}
