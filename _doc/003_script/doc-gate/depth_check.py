#!/usr/bin/env python3
"""depth_check.py — 抓「按目录深度上溯仓根」和 `_doc/` 路径字面量在搬桶后断链的地方。

补 doc_audit.py R6 的盲区：R6 只看 `.sh` 的 `cd "$(dirname "$0")"`，而 Python/Java 里
`os.path.join(HERE, os.pardir, os.pardir)` 这类**按层数**求仓根的写法，桶的层级一变
（acceptance 那一格从两层变三层）就静默指到别处，不报错、只找错东西。

用法：
    python3 z-boot/_doc/003_script/depth_check.py               # 扫全部在范围内的仓
    python3 z-boot/_doc/003_script/depth_check.py z-bot         # 只扫指定仓
    python3 z-boot/_doc/003_script/depth_check.py --root <dir>   # 换组织根（自检用）

判据：
    A 深度上溯：`VAR = os.path.join(<here>, os.pardir, ...)` 这类赋值，以及 shell 里
      `cd "$SCRIPT_DIR"` 后接的 `..` 串 —— 上溯级数必须等于该文件相对仓根的目录深度
    B 字面量：源码/配置里出现的 `_doc/...` 拼到仓根后必须真实存在
      —— 三类不算断链：跨仓引用（同行有 `../` 或 `z-xxx/_doc`）、测试在临时目录里自己造的
      形状（`.resolve(` / `Paths.get(`）、从旧提交取 blob 的历史 pin。确实要留旧路径写法的行，
      行尾加 `DC:ignore` 显式免检。

已知局限：组件拼接的路径（`"_doc" + File.separator + "002_deploy"`、
`os.path.join(REPO, "_doc", "005_testing", ...)`）B 看不见，得靠 A 或人工。
退出码：有违规则为 1。
"""
import os
import re
import subprocess
import sys

BUCKET_SRC_EXT = (".py", ".sh")
SCAN_EXT = (".py", ".sh", ".java", ".xml", ".yml", ".yaml")

# 只在「看起来是在定位仓根」的赋值里查上溯级数，避免误伤普通 ../ 字符串
ROOTVARS = ("ZBOT", "REPO", "ROOT", "REPO_ROOT", "PROJECT_ROOT", "ROOT_DIR", "BASE", "ORG")
PARDIR = re.compile(r"os\.pardir|\.\.(?=[" + "'" + r"/])")
ROOT_ASSIGN = re.compile(r'^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*os\.path\.(?:join|abspath).*)$')
# 路径字符集必须收死：只认 ASCII 路径字符。Java 的 `{@code …归档名.md}`、中文注释里带尾随
# 括号/中文的同一形状，若字符集放宽就会把尾随内容一起吃进去，制造一片假悬空
LITERAL = re.compile(r"(_doc/[A-Za-z0-9_./\-]{3,})")
PLACEHOLDER = re.compile(r"\.\.\.|00X|\bX{2,}")
# 跨仓引用与本仓无关：`"$ORG/../_doc/001_feature"`（z-graph 脚本里指 z-opc）、
# `"z-opc/_doc/005_skills"`（z-skill 语料测试）—— 都不是本仓的断链
CROSS_REPO = re.compile(r"\.\./|z-[a-z0-9-]+/_doc")
# 测试在临时目录里自己造的形状，同样不指本仓
SCRATCH = re.compile(r"\.resolve\(|Paths?\.get\(|Path\.of\(")
CDUP = re.compile(r'cd\s+"?\$?\{?S(?:CRIPT_)?DIR\}?((?:/\.\.)+)')

# 历史 pin：这类行是故意引用**旧**路径的（从旧提交取 blob），报出来就是假阳性
PIN = re.compile(r'git\s+show\s|\bSEALED_PATH\b|\bblob\b')


def repos(org):
    excluded = {"z-opc", "z-opc-foundation-lead", "z-opcs-server"}  # 与 doc_audit.py 同口径
    return sorted(d for d in os.listdir(org)
                  if os.path.isdir(os.path.join(org, d, ".git")) and d not in excluded)


def files(org, repo):
    res = subprocess.run(["git", "-C", os.path.join(org, repo), "-c", "core.quotepath=false",
                          "ls-files", "-z"], capture_output=True, text=True, check=True)
    return [p for p in res.stdout.split("\0") if p.endswith(SCAN_EXT)]


def depth(rel):
    return len(rel.split("/")) - 1


def check(org, repo):
    bad = []
    for rel in files(org, repo):
        path = os.path.join(org, repo, rel)
        if not os.path.isfile(path):
            continue
        d = depth(rel)
        with open(path, encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
        for i, line in enumerate(lines, 1):
            if rel.endswith(BUCKET_SRC_EXT) and not line.lstrip().startswith("#"):
                m = ROOT_ASSIGN.search(line)
                if m and m.group(1).upper() in ROOTVARS:
                    ups = len(PARDIR.findall(m.group(2)))
                    if ups and ups != d:
                        bad.append((rel, i, f"A {m.group(1)} 上溯 {ups} 级，但该文件距仓根 {d} 层"))
                m = CDUP.search(line)
                if m:
                    ups = m.group(1).count("/..")
                    if ups != d:
                        bad.append((rel, i, f"A cd \"$SCRIPT_DIR/..\" 上溯 {ups} 级，但该文件距仓根 {d} 层"))
            if PIN.search(line) or "DC:ignore" in line:
                continue
            for m in LITERAL.finditer(line):
                lit = m.group(1).rstrip(".,:;/")
                if "$" in lit or "{" in lit or not lit or PLACEHOLDER.search(lit):
                    continue
                # `_doc` 前面还有一段路径（`z-opc/_doc/…`、`$WORK/prey/_doc/…`）或 `../`
                # ⇒ 指的是别的仓/临时树，不是本仓断链
                head = line[:m.start()]
                if head.endswith("/") or CROSS_REPO.search(head) or SCRATCH.search(head):
                    continue
                if not os.path.exists(os.path.join(org, repo, lit)):
                    bad.append((rel, i, f"B 悬空字面量 {lit}"))
    return bad


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    argv = sys.argv[1:]
    # 仓根 = 向上第一个含 .git 的目录（与 doc_audit 同款：不用固定层数上溯，搬家不怕断链）
    root = here
    while not os.path.isdir(os.path.join(root, ".git")):
        parent = os.path.dirname(root)
        if parent == root:
            print("depth_check.py: 向上找不到 .git，无法定位仓根（fail-closed）", file=sys.stderr)
            return 2
        root = parent
    org = os.path.dirname(root)
    if "--root" in argv:
        org = os.path.abspath(argv[argv.index("--root") + 1])
        argv = argv[:argv.index("--root")] + argv[argv.index("--root") + 2:]
    targets = argv or repos(org)
    if not targets:  # 零输入也会打印"0 违规"，那是假绿
        print(f"错误：{org} 下没找到任何在范围内的仓", file=sys.stderr)
        return 2
    total = 0
    for r in targets:
        if not os.path.isdir(os.path.join(org, r, ".git")):
            print(f"错误：{os.path.join(org, r)} 不是 git 仓（点名的仓必须存在，否则静默漏扫）",
                  file=sys.stderr)
            return 2
        bad = check(org, r)
        total += len(bad)
        if bad:
            print(f"=== {r}")
            for rel, i, msg in bad:
                print(f"  {rel}:{i} {msg}")
    print(f"\n扫描 {len(targets)} 仓，违规 {total} 条")
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main())
