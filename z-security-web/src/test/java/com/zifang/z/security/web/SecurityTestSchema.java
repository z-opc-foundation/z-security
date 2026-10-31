package com.zifang.z.security.web;

import javax.sql.DataSource;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.Statement;
import java.util.stream.Collectors;

/**
 * 测试用表结构（**从生产 DDL 脚本读**，不手写第二份）。
 *
 * <p><b>为什么要读脚本而不是内嵌 DDL</b>：内嵌一份 DDL ⇒ 生产脚本改了测试不改
 * ⇒ 测试全绿但生产炸。手写两份必然漂移。本类直接读
 * {@code _doc/002_deploy/init.sql}（仓内路径），保证「测的就是要上的」。
 *
 * @author zifang
 */
final class SecurityTestSchema {

    /** DDL 脚本路径（相对仓根）。 */
    private static final String DDL_PATH = "../_doc/002_deploy/init.sql";

    private SecurityTestSchema() {
    }

    /**
     * 建表（幂等）。
     *
     * @param dataSource 本域数据源
     * @throws Exception 建表失败
     */
    static void apply(DataSource dataSource) throws Exception {
        String ddl = readDdl();
        try (Connection conn = dataSource.getConnection(); Statement st = conn.createStatement()) {
            for (String sql : splitStatements(ddl)) {
                st.execute(sql);
            }
        }
    }

    /** 读 DDL 脚本。 */
    private static String readDdl() {
        java.nio.file.Path path = java.nio.file.Path.of(DDL_PATH).toAbsolutePath().normalize();
        try (InputStream in = java.nio.file.Files.newInputStream(path)) {
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
                return reader.lines().collect(Collectors.joining("\n"));
            }
        } catch (Exception e) {
            throw new IllegalStateException("读 DDL 失败：" + path, e);
        }
    }

    /**
     * 切分 SQL 语句（按分号切，忽略注释行）。
     *
     * @param ddl DDL 全文
     * @return 语句列表
     */
    private static java.util.List<String> splitStatements(String ddl) {
        java.util.List<String> statements = new java.util.ArrayList<>();
        StringBuilder current = new StringBuilder();
        for (String line : ddl.split("\n")) {
            String trimmed = line.trim();
            if (trimmed.startsWith("--") || trimmed.isEmpty()) {
                continue;
            }
            current.append(line).append('\n');
            if (trimmed.endsWith(";")) {
                String sql = current.toString().trim();
                statements.add(sql.substring(0, sql.length() - 1));
                current.setLength(0);
            }
        }
        if (current.toString().trim().length() > 0) {
            statements.add(current.toString().trim());
        }
        return statements;
    }
}
