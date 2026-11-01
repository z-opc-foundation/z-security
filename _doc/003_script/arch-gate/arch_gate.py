#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
架构守门人（ratchet gate）：CI 里跑，防止架构质量回潮。

机制 —— 棘轮基线：
  · 基线文件记录每仓每类硬缺陷的数量（baseline.json）
  · 本轮抽取后与基线对比：
      变多 ⇒ exit 1（CI 挡住，禁止合入）并打印新增明细
      变少 ⇒ exit 0，并提示「可运行 --update 收紧基线」
  · 基线只进不退 ⇒ 架构债单调递减，整改成果被永久锁定

用法：
  python3 arch_gate.py <arch_dir>                                # 校验（CI 模式）
  python3 arch_gate.py <arch_dir> --update                       # 整改后收紧基线
  python3 arch_gate.py <arch_dir> --init                         # 首次建立基线
  python3 arch_gate.py <arch_dir> --baseline <path>              # 显式指定基线文件位置
                                                                   （CI 里必须用：默认在
                                                                    arch_dir 找不到基线会
                                                                    静默 --init ⇒ 棘轮假绿）
"""
import io
import json
import os
import sys

KINDS = ("bypass", "up", "cycle", "modrole", "skip", "conflict", "xsame")


def count_errors(arch_dir):
    """按仓统计硬缺陷数。"""
    import glob
    result = {}
    for fn in sorted(glob.glob(os.path.join(arch_dir, "*.arch.json"))):
        repo = os.path.basename(fn)[:-len(".arch.json")]
        d = json.load(io.open(fn, encoding="utf-8"))
        c = {k: 0 for k in KINDS}
        for v in d["violations"]:
            if v.get("level") == "err" and v["kind"] in c:
                c[v["kind"]] += 1
        result[repo] = c
    return result


def main():
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    d = sys.argv[1]
    update = "--update" in sys.argv
    init = "--init" in sys.argv
    baseline_path = os.path.join(d, "gate-baseline.json")
    if "--baseline" in sys.argv:
        baseline_path = sys.argv[sys.argv.index("--baseline") + 1]

    cur = count_errors(d)

    if init or not os.path.exists(baseline_path):
        with io.open(baseline_path, "w", encoding="utf-8") as f:
            json.dump(cur, f, ensure_ascii=False, indent=1)
        total = sum(sum(c.values()) for c in cur.values())
        print("基线已建立：硬缺陷总数 %d（%d 仓）" % (total, len(cur)))
        return

    base = json.load(io.open(baseline_path, encoding="utf-8"))
    worse, better = [], []
    for repo in sorted(set(base) | set(cur)):
        b = base.get(repo, {k: 0 for k in KINDS})
        c = cur.get(repo, {k: 0 for k in KINDS})
        for k in KINDS:
            if c[k] > b[k]:
                worse.append("%s: %s %d → %d（+%d）" % (repo, k, b[k], c[k], c[k] - b[k]))
            elif c[k] < b[k]:
                better.append("%s: %s %d → %d（-%d）" % (repo, k, b[k], c[k], b[k] - c[k]))

    if worse:
        print("✗ 架构守门失败 —— 以下硬缺陷较基线**新增**：")
        for w in worse:
            print("   ", w)
        print("\n处理：修复新增缺陷，或（确属误判）在抽取器修判据后重跑 --update")
        sys.exit(1)

    if better:
        print("✓ 架构守门通过 —— 本轮改善 %d 处：" % len(better))
        for b in better[:10]:
            print("   ", b)
        if update:
            with io.open(baseline_path, "w", encoding="utf-8") as f:
                json.dump(cur, f, ensure_ascii=False, indent=1)
            print("基线已收紧（棘轮锁位）")
        else:
            print("提示：跑 --update 可锁定改善成果")
    else:
        print("✓ 架构守门通过 —— 与基线持平")


if __name__ == "__main__":
    main()
