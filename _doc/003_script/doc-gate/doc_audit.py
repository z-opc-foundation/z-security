#!/usr/bin/env python3
"""doc_audit.py — 按 002_项目文档收口规范 扫描 z-opc-foundation 下各项目仓的文档收口合规。

用法：
    python3 _doc/003_script/doc-gate/doc_audit.py            # 扫全部在范围内的仓
    python3 _doc/003_script/doc-gate/doc_audit.py z-mq z-lc  # 只扫指定仓

检查项（与规范的 audit 检查项一一对应）：
    R1 仓根除允许清单外无散落 .md/.txt/.sql/.sh/.py
    R2 _doc/ 根不留散文件（README.md 索引除外）
    R3 _doc/ 下的一级目录必须命中固定编号表
    R4 不留空桶（git 不跟踪空目录，留着就是 README 断链的来源）
    R5 README.md 无指向不存在路径的相对链接
    R5b README「## 文档目录」章节与 _doc/ 下真实存在的桶双向一致（漏列 / 列空桶 / 该有章节而没有）
    R6 _doc/003_script 下依赖仓根的脚本必须用 REPO_ROOT 上溯定位，不能 cd "$(dirname $0)"
    R7 运行态/临时件不进 git：一律写 <仓>/.cache/，且 .cache 必须被 ignore
    R8 桶内文件用 NN-slug.md 前缀（规范「三条硬规则」第 3 条：号段归桶所有）；
       不得用 -2 后缀绕重名，同一桶内 NN 不得重复
    R9 _doc/001_arch/ 必须存在且含项目总览 00-overview.md（规范：001_arch 是唯一强制桶）
    R13 仓根 README.md 体量下限：≥60 行且 ≥6 个二级章节
       （lead README「项目仓 README 口径」第 6 条；此前只写在口径正文、尺子没查）
退出码：有违规则为 1。
"""
import os
import re
import subprocess
import sys
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
# 仓根 = 向上第一个含 .git 的目录（R6 精神：不用固定层数上溯，脚本住几层都不怕搬家）
ROOT = HERE
while not os.path.isdir(os.path.join(ROOT, ".git")):
    _parent = os.path.dirname(ROOT)
    if _parent == ROOT:
        raise SystemExit("doc_audit.py: 向上找不到 .git，无法定位仓根（fail-closed）")
    ROOT = _parent
ORG = os.path.dirname(ROOT)

ALLOWED_ROOT = {
    "README.md", "CHANGELOG.md", "LICENSE", "AGENTS.md", "CLAUDE.md", "pom.xml",
    "build.gradle", ".gitignore", ".dockerignore", ".flattened-pom.xml",
    "Makefile", "mvnw", "mvnw.cmd", "package.json", "package-lock.json",
    "tsconfig.json", "tsconfig.build.json", "vite.config.ts", "vite.lib.config.ts",
    "vitest.config.ts", "pnpm-workspace.yaml", "pnpm-lock.yaml",
}
ALLOWED_RE = re.compile(
    r"^(docker-compose[\w.-]*\.ya?ml|Dockerfile[\w.-]*|\.env\.[\w-]+|"
    r"settings[\w.-]*\.xml|\.gitkeep|sonar[\w.-]*|license-check[\w.-]*)$")

BUCKETS = {
    "001_arch", "002_deploy", "003_script", "004_skill",
    "005_testing", "006_release", "007_backlog", "008_troubleshooting",
}
# z-opc 单体本轮未并表；lead 仓保留自己的 001-008 结构
EXCLUDED = {"z-opc", "z-opc-foundation-lead", "z-opcs-server"}

STRAY_EXT = (".md", ".MD", ".txt", ".sql", ".sh", ".py", ".rst", ".adoc")

# R8：桶内文件的 NN-slug 命名
NN_NAME = re.compile(r"^\d{2,3}[-_]")
DASH2 = re.compile(r"-\d+\.md$")
# 日期后缀（-2026-10-31.md）会被 DASH2 误判成「-2 后缀绕重名」，先排除
DATE_SUFFIX = re.compile(r"\d{4}-\d{2}-\d{2}\.md$")
# 平台约定文件不参与 NN 编号（GitHub / AI 工具按固定名找它们）
NAME_EXEMPT = {"README.md", "AGENTS.md", "SKILL.md", "CLAUDE.md"}

ROOT_CD = re.compile(r'cd\s+"\$\(\s*dirname[^)]*\$0[^)]*\)')
# 只有确实按仓根取物（pom.xml / .env / .gnupg / ~/.m2）的脚本，cd 到 _doc/003_script 才算断链
ROOT_DEP = re.compile(r'(pom\.xml|\.env|\.gnupg|settings\.xml)')

# R7：跑起来才会产生的东西不进 git（E2E 的假 home、字节码缓存、锁、sqlite、日志）
RUNTIME_SHAPE = re.compile(
    r'(^|/)__pycache__/|\.pyc$|(^|/)state\.db$|\.lock$|(^|/)checkpoints/'
    r'|(^|/)logs?/[^/]*\.log$|/out/profile-[^/]+/|(^|/)\.DS_Store$')

# 依赖锁定文件是包管理器产物，必须入仓（口径第 3 条白名单里的「lock」）；
# 与运行期锁 state.lock / index.lock 形状相同，只能按文件名区分。
DEP_LOCK = re.compile(
    r'(^|/)(Cargo\.lock|pubspec\.lock|package-lock\.json|pnpm-lock\.yaml|yarn\.lock'
    r'|npm-shrinkwrap\.json|poetry\.lock|Pipfile\.lock|uv\.lock|composer\.lock'
    r'|Gemfile\.lock|mix\.lock|flake\.lock|bun\.lockb)$')


def is_runtime_artifact(path):
    return bool(RUNTIME_SHAPE.search(path)) and not DEP_LOCK.search(path)

# R13：README 体量下限（lead README「项目仓 README 口径」第 6 条）
#   「≥ 60 行且 ≥ 6 个二级章节，防止再次退化成模板空壳。」
#   这条此前只写在口径正文、尺子没查 —— 与 R5b / R8 / R9 同族，本轮补进尺子。
MIN_README_LINES = 60
MIN_README_H2 = 6


def tracked(repo, ref=None):
    if ref:
        res = subprocess.run(["git", "-C", os.path.join(ORG, repo), "ls-tree", "-r",
                              "--name-only", "-z", ref],
                             capture_output=True, text=True, check=True)
    else:
        res = subprocess.run(["git", "-C", os.path.join(ORG, repo), "ls-files", "-z"],
                             capture_output=True, text=True, check=True)
    return [p for p in res.stdout.split("\0") if p]


def ignore_blob(repo, ref=None):
    """.gitignore 全文：ref 模式读历史版本，用于拿已知坏样本喂 R7。"""
    if ref:
        res = subprocess.run(["git", "-C", os.path.join(ORG, repo), "show", f"{ref}:.gitignore"],
                             capture_output=True, text=True)
        return res.stdout
    path = os.path.join(ORG, repo, ".gitignore")
    return open(path, encoding="utf-8", errors="replace").read() if os.path.isfile(path) else ""


def docker_build_inputs(repo):
    """被 Dockerfile / docker-compose 引用的仓根文件名 —— 规范豁免：搬走即断构建。"""
    names = set()
    for p in tracked(repo):
        base = p.rsplit("/", 1)[-1]
        if not (base == "Dockerfile" or base.startswith("Dockerfile.") or base.endswith((".yml", ".yaml"))):
            continue
        if not os.path.isfile(os.path.join(ORG, repo, p)):
            continue
        with open(os.path.join(ORG, repo, p), encoding="utf-8", errors="replace") as fh:
            for line in fh:
                for tok in re.split(r"[\s,'\"\[\]]+", line):
                    if "/" not in tok and tok.endswith((".py", ".sh", ".jar", ".cjs", ".js")):
                        names.add(tok)
    return names


def has_ignored_content(repo, bucket):
    """桶里只剩被 .gitignore 定向忽略的私有件 —— 不算空桶，按规范保留原位。"""
    res = subprocess.run(
        ["git", "-C", os.path.join(ORG, repo), "ls-files", "--others", "--ignored",
         "--exclude-standard", "-z", f"_doc/{bucket}/"],
        capture_output=True, text=True, check=True)
    return any(p for p in res.stdout.split("\0") if p)


def readme_doc_buckets(repo):
    """解析 README「## 文档目录」章节里**以链接形态声明**的桶集合。

    返回 (声明的桶集合, 有没有该章节)。
    只认 markdown 链接目标 `_doc/<NNN_xxx>/…` —— 散文里写「`001_arch/` 本仓不存在」
    是**如实记录**（规范明确说"不建链接以免留下断链"），不算声明。
    """
    readme = os.path.join(ORG, repo, "README.md")
    if not os.path.isfile(readme):
        return set(), False
    with open(readme, encoding="utf-8") as fh:
        txt = fh.read()
    m = re.search(r"^##\s*文档目录\s*$", txt, re.M)
    if not m:
        return set(), False
    rest = txt[m.end():]
    nxt = re.search(r"^##\s", rest, re.M)
    sec = rest[:nxt.start()] if nxt else rest
    return set(re.findall(r"\]\(_doc/(\d{3}_[a-z]+)/", sec)), True


def strip_fences(txt):
    """剔除围栏代码块（``` / ~~~）。

    R13 数二级章节时必须先剔围栏 —— 否则文件里贴一段带 '## ' 的目录树/日志
    就会被误计成章节数，尺子会「虚高通过」。
    """
    out, fence = [], None
    for line in txt.splitlines():
        m = re.match(r"^\s*(```+|~~~+)", line)
        if fence is not None:
            if m and line.strip().startswith(fence):
                fence = None
            continue
        if m:
            fence = m.group(1)[:3]
            continue
        out.append(line)
    return out


def readme_bulk(repo):
    """仓根 README 的体量读数：(总行数, 二级章节数)。

    行数 = 文件全部行（splitlines 计数，代码块计入 —— 口径要的是「体量」）。
    章节数 = 剔除围栏代码块后以 `## ` 开头的标题行数（`### ` 不算二级章节）。
    无 README 时返回 None。
    """
    path = os.path.join(ORG, repo, "README.md")
    if not os.path.isfile(path):
        return None
    with open(path, encoding="utf-8", errors="replace") as fh:
        txt = fh.read()
    lines = txt.splitlines()
    h2 = [l for l in strip_fences(txt) if re.match(r"^##\s+\S", l)]
    return len(lines), len(h2)


def check(repo, ref=None):
    bad = []
    files = tracked(repo, ref)
    top = {p for p in files if "/" not in p}
    exempt = docker_build_inputs(repo)

    for name in sorted(top):
        if name in ALLOWED_ROOT or ALLOWED_RE.match(name):
            continue
        if name in exempt:
            continue
        if name.endswith(STRAY_EXT):
            bad.append(("R1", f"仓根散件 {name}"))

    doc_files = [p for p in files if p.startswith("_doc/")]
    for p in doc_files:
        if p.count("/") == 1 and p != "_doc/README.md":  # DC:ignore 比的是索引里的路径形状，不是盘上引用
            bad.append(("R2", f"_doc 根散文件 {p}"))

    buckets = {p.split("/")[1] for p in doc_files if p.count("/") >= 2}
    for b in sorted(buckets - BUCKETS):
        bad.append(("R3", f"非编号表目录 _doc/{b}/"))

    docdir = os.path.join(ORG, repo, "_doc")
    if os.path.isdir(docdir):
        on_disk = {d for d in os.listdir(docdir) if os.path.isdir(os.path.join(docdir, d))}
        for d in sorted(on_disk - buckets - {"README.md"}):
            if has_ignored_content(repo, d):
                continue
            bad.append(("R4", f"空桶 _doc/{d}/（git 不跟踪空目录，clone 后必断链）"))

    readme = os.path.join(ORG, repo, "README.md")
    if os.path.isfile(readme):
        with open(readme, encoding="utf-8") as fh:
            for i, line in enumerate(fh, 1):
                for tgt in re.findall(r"\]\(([^)\s]+)", line):
                    if tgt.startswith(("#", "http://", "https://", "mailto:", "git@")):
                        continue
                    path = tgt.split("#")[0]
                    if path and not os.path.exists(os.path.join(ORG, repo, path)):
                        bad.append(("R5", f"README L{i} 断链 {path}"))

    # R5b：README「文档目录」必须与 _doc/ 下真实存在的桶**双向一致**
    # —— 规范原文：「段落必须与该仓 _doc/ 下真实存在的目录一一对应 ——
    # 列空桶或不列已存在的桶都算不合规」。这条 2026-10-19 之前只写在规范正文里、
    # 尺子没查（当时的 R5 只查断链），本轮补进尺子。
    real_buckets = set()
    if os.path.isdir(docdir):
        for d in os.listdir(docdir):
            p = os.path.join(docdir, d)
            if not os.path.isdir(p) or d == "README.md":
                continue
            if d in buckets or has_ignored_content(repo, d):
                real_buckets.add(d)
    declared, has_section = readme_doc_buckets(repo)
    if real_buckets and not has_section:
        bad.append(("R5b", f"README 缺「## 文档目录」章节（仓内实有 {len(real_buckets)} 个桶："
                            f"{', '.join(sorted(real_buckets))}）"))
    elif has_section:
        for d in sorted(real_buckets - declared):
            bad.append(("R5b", f"README「文档目录」漏列已存在的桶 _doc/{d}/"))
        for d in sorted(declared - real_buckets):
            bad.append(("R5b", f"README「文档目录」列了不存在的桶 _doc/{d}/"))
    elif not real_buckets and has_section and not os.path.isdir(docdir):
        bad.append(("R5b", "README 有「## 文档目录」章节但仓内无 _doc  目录（规范：_doc 不存在则不得有该章节）"))

    # R5c：_doc/ 下的 markdown 相对链接同样必须落地
    #     R5 只看**仓根** README.md，而 _doc/ 里的文档互相引用同样会烂 ——
    #     桶内改名（NN-slug 归一）之后，老文件里的旧名链接不会自动跟着改。
    #     2026-10-19 补进尺子：实测 z-mq 的 08-design.md 仍指着改名前的
    #     ./技术架构.md，z-cache / z-ctc / z-schedule / z-util / z-graph 各有 1 处。
    for p in doc_files:
        if not p.endswith(".md"):
            continue
        full = os.path.join(ORG, repo, p)
        if not os.path.isfile(full):
            continue
        with open(full, encoding="utf-8", errors="replace") as fh:
            body = fh.read()
        base_dir = os.path.dirname(full)
        for i, line in enumerate(body.splitlines(), 1):
            for tgt in re.findall(r"\]\(([^)\s]+)", line):
                if tgt.startswith(("#", "http://", "https://", "mailto:", "git@", "file://")):
                    continue
                if "<" in tgt or ">" in tgt:      # 文档里举例用的占位形状（如 `_doc/<d>/`）
                    continue
                path = urllib.parse.unquote(tgt.split("#")[0])
                if not path:
                    continue
                if os.path.exists(os.path.join(base_dir, path)):
                    continue
                if os.path.exists(os.path.join(ORG, repo, path)):
                    continue
                bad.append(("R5c", f"{p} L{i} 断链 {tgt}"))

    # R9 001_arch 是**唯一强制桶**，且必须含项目总览
    #    规范依据：002 规范 §"三条硬规则"第 1 条「桶按需建 —— 没有内容就不建这个目录
    #    （001_arch 除外）」+ §"audit 检查项"第 3 条「_doc/001_arch/ 存在且含项目总览」。
    #    这条此前只写在规范正文、尺子没查（与 R5b / R8 同族），本轮补进尺子。
    if "001_arch" not in buckets:
        bad.append(("R9", "缺 _doc/001_arch/（规范：唯一强制桶，桶按需建但它除外）"))
    elif "_doc/001_arch/00-overview.md" not in files:
        bad.append(("R9", "_doc/001_arch/ 存在但缺项目总览 00-overview.md"
                          "（规范 audit 检查项：001_arch 存在且含项目总览）"))

    # R13 README 体量下限 —— 口径第 6 条
    #    「≥ 60 行且 ≥ 6 个二级章节，防止再次退化成模板空壳。」
    #    此前只写在 lead README 的口径正文里、尺子没查，所以 4 个仓退化成短壳都没人拦。
    bulk = readme_bulk(repo)
    if bulk is not None:
        n_lines, n_h2 = bulk
        if n_lines < MIN_README_LINES:
            bad.append(("R13", f"README.md 体量不足：{n_lines} 行 < {MIN_README_LINES} 行"
                              f"（口径第 6 条，防模板空壳）"))
        if n_h2 < MIN_README_H2:
            bad.append(("R13", f"README.md 二级章节不足：{n_h2} 个 < {MIN_README_H2} 个"
                              f"（口径第 6 条，防模板空壳）"))

    for p in files:
        if not (p.startswith("_doc/003_script/") and p.endswith(".sh")):
            continue
        if not os.path.isfile(os.path.join(ORG, repo, p)):
            continue  # ref 模式下旧路径已不在盘上
        with open(os.path.join(ORG, repo, p), encoding="utf-8", errors="replace") as fh:
            body = fh.read()
        if ROOT_CD.search(body) and "REPO_ROOT" not in body and ROOT_DEP.search(body):
            bad.append(("R6", f"{p} 用 cd \"$(dirname $0)\" 定位，搬到 _doc 后必 die"))

    # R7 运行态件不进 git
    for p in files:
        if is_runtime_artifact(p):
            bad.append(("R7", f"运行态件进了 git：{p}（该写 <仓>/.cache/）"))
    cache_tracked = [p for p in files if p.split("/")[0] == ".cache"]
    ignores = ignore_blob(repo, ref)
    if cache_tracked:
        bad.append(("R7", f".cache/ 里有 {len(cache_tracked)} 个被跟踪文件（例：{cache_tracked[0]}）"))
    if ("/.cache/" not in ignores and ".cache/" not in ignores):
        bad.append(("R7", ".gitignore 没有 /.cache/ —— 临时件无处可放"))

    # R8 桶内 NN-slug 命名
    # 只看**桶直属**文件：007_backlog 的「一个事项一个 featureNNN_<slug>/ 子目录」是规范
    # 要求的形状，子目录内部的号段在本子目录内排序，不与兄弟子目录比较。
    for bucket in sorted(buckets):
        nn_seen = {}
        for p in files:
            if not p.startswith(f"_doc/{bucket}/"):
                continue
            if p.count("/") != 2:      # _doc/<bucket>/<file> —— 更深的归子目录，不管
                continue
            name = p.rsplit("/", 1)[-1]
            if not name.endswith(".md") or name in NAME_EXEMPT:
                continue
            if DASH2.search(name) and not DATE_SUFFIX.search(name):
                bad.append(("R8", f"{p} 用 -2 后缀绕重名（规范：该合并成一份，或换号）"))
                continue
            m = NN_NAME.match(name)
            if not m:
                bad.append(("R8", f"{p} 桶内文件缺 NN-slug 前缀（规范：桶内用 NN-slug.md，NN 只在本桶排序）"))
                continue
            nn = m.group(0)
            if nn in nn_seen:
                bad.append(("R8", f"{p} 的号段 {nn} 与同桶的 {nn_seen[nn]} 重复（号段只在本桶排序，须唯一）"))
            else:
                nn_seen[nn] = p

    return bad


def main():
    repos = sys.argv[1:] or sorted(
        d for d in os.listdir(ORG)
        if os.path.isdir(os.path.join(ORG, d, ".git")) and d not in EXCLUDED)
    total = 0
    ref = None
    if "--against" in sys.argv:
        k = sys.argv.index("--against")
        ref = sys.argv[k + 1]
        repos = sys.argv[:k] + sys.argv[k + 2:]
        repos = [r for r in repos if not r.startswith("-")] or [
            d for d in os.listdir(ORG)
            if os.path.isdir(os.path.join(ORG, d, ".git")) and d not in EXCLUDED]
    for r in repos:
        if not os.path.isdir(os.path.join(ORG, r, ".git")):
            # 指名要扫的仓（单仓模式，CI 里）不存在 ⇒ fail-closed，不许静默跳过。
            # 否则 git 环境坏掉时守门人恒绿 —— 与 arch-gate 假绿同类（2026-11-01 教训）。
            if len(sys.argv) > 1 and r in sys.argv[1:]:
                print(f"✗ 仓目录不存在或缺 .git：{os.path.join(ORG, r)}", file=sys.stderr)
                return 2
            continue
        try:
            bad = check(r, ref)
        except subprocess.CalledProcessError as e:
            # git 执行失败（环境坏/非 git 目录）在守门语义下必须挡合入，不能当「合规」放过。
            print(f"✗ {r}: git 调用失败，无法审计（fail-closed）：{e}", file=sys.stderr)
            total += 1
            continue
        total += len(bad)
        if bad:
            print(f"=== {r}")
            for code, msg in bad:
                print(f"  [{code}] {msg}")
    print(f"\n扫描 {len(repos)} 仓，违规 {total} 条")
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main())
