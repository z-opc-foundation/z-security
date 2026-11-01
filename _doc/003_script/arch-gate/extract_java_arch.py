#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
从真实 Java 源码里抽出「最小单元」架构图。

不手编任何依赖：调用边、注入关系、跨服务调用、Kafka 主题，全部从 .java 源码解析。

抽出来的东西
  unit  单元 = 一个有业务方法的类（Service / Controller / Consumer / Producer / Repository / Feign）
  call  同服务内 A 调 B
  xsvc  跨服务调用（Feign）
  kafka 消息投递（Producer → Consumer）
  layer L1..L4 / X  层位，由调用图推导

层位规则（自底向上迭代）
  L1 资源层  repo / producer / consumer / feign —— 真碰存储、消息、外部
  L2 能力层  service，业务下游 ≤1
  L3 编排层  service，业务下游 ≥2
  L4 入口层  被 Controller 直接调的 service
  X  横切层  mapper / config / handler / 纯 DTO

用法：python3 extract_java_arch.py <repo_root> > out.json
"""
import io
import json
import os
import re
import sys
from collections import defaultdict

# ───────────────── 词法 ─────────────────
def strip_comments(src):
    out, i, n = [], 0, len(src)
    while i < n:
        c = src[i]
        if c in '"\'':
            q = c; out.append(c); i += 1
            while i < n:
                if src[i] == '\\':
                    out.append(src[i:i+2]); i += 2; continue
                out.append(src[i])
                if src[i] == q: i += 1; break
                i += 1
            continue
        if src.startswith("//", i):
            j = src.find("\n", i); i = n if j < 0 else j; continue
        if src.startswith("/*", i):
            j = src.find("*/", i); i = n if j < 0 else j + 2; continue
        out.append(c); i += 1
    return "".join(out)


RE_PACKAGE = re.compile(r"^\s*package\s+([\w.]+)\s*;", re.M)
RE_CLASS   = re.compile(r"\b(?:public\s+|final\s+|abstract\s+)*(class|interface|enum|record)\s+(\w+)")
RE_ANNOT   = re.compile(r"@(\w+)")
# 字段声明。注意要排除 static（常量不是注入依赖）。
# ⚠ 原正则只吃掉一个 final，于是 "private static final String SCRIPT_HANDLER = ..."
#   被解析成 类型="static final String" —— 常量混进依赖表，污染调用边。
RE_FIELD   = re.compile(
    r"^\s*(?:private|protected|public)\s+(?!static\b)(?:final\s+)?([\w<>,\.\[\]\s]+?)\s+(\w+)\s*(?:[=;])", re.M)
RE_METHOD  = re.compile(
    r"^\s*(?:public|protected|private)\s+(?:static\s+)?(?:final\s+)?(?:synchronized\s+)?"
    r"([\w<>,\.\[\]\s]+?)\s+(\w+)\s*\(([^)]*)\)\s*(?:throws[\w,\s\.]*)?\{", re.M)
RE_CALL    = re.compile(r"\b(?:this\s*\.\s*)?(\w+)\s*\.\s*(\w+)\s*\(")
RE_IMPORT  = re.compile(r"^\s*import\s+(?:static\s+)?([\w.]+)\s*;", re.M)

# ⚠ 方法签名**不能用正则**。
#   正则版 `([^)]*)\s*\{` 会被参数里的嵌套括号截断：
#   `public Result<Map<String,Object>> list(@RequestParam(name="x", required=false) String c)`
#   参数中的 `)` 让 `[^)]*` 提前结束，后面又要求紧跟 `{` ⇒ 整条失配 ⇒ **方法全丢**。
#   实测 z-opc 仓 GrayCandidateController（3 个方法）被解析成 0 个方法。
#   ⇒ 改为手写扫描：找 `(` 后做括号配平，再看 `)` 之后是不是 `{`。
RE_MODIFIERS = ("public", "protected", "private")

# 值类型（不是依赖）：配置值、简单标量
VALUE_TYPES = {
    "String", "int", "long", "Integer", "Long", "Short", "Byte", "Double",
    "Float", "Boolean", "boolean", "char", "Character", "byte", "short",
    "BigDecimal", "BigInteger", "Date", "LocalDate", "LocalDateTime",
    "Duration", "Object", "void", "Pattern", "Matcher", "UUID",
}
RE_RET_START = re.compile(r"^\s*(?:public|protected|private)\s+(?:static\s+)?(?:final\s+)?"
                          r"(?:synchronized\s+)?(?:abstract\s+)?(?:default\s+)?"
                          # ⚠ 字符类必须含 ?：泛型通配符 Result<?> / List<? extends X>
                          #   缺了它整个方法被跳过（z-team SkillsController 8 个方法全丢）。
                          r"([\w$?<>\[\]\.,\s]+?)\s+(\w+)\s*\(", re.M)

# 触发型注解（方法级）—— 用于定位「事件/定时驱动源」
TRIGGER_ANNOS = ("EventListener", "Scheduled", "KafkaListener", "RocketMQMessageListener",
                 "RabbitListener", "TransactionalEventListener", "XxlJob", "JobHandler")
# 用于在类体里找方法起点（与 scan_methods 同构，但只看方法头）
RE_TRIGGER_SCAN = re.compile(
    r"^\s*(?:public|protected|private)\s+(?:static\s+)?(?:final\s+)?(?:synchronized\s+)?"
    r"(?:abstract\s+)?(?:default\s+)?[\w$<>\[\]\.,\s]+?\s+\w+\s*\(", re.M)


def scan_methods(body):
    """手写方法签名扫描器。返回 [(方法名, 方法体)]。

    判据：
      ① 修饰符开头（public/protected/private）
      ② 返回类型 + 方法名 + `(`
      ③ 括号配平找 `)`
      ④ `)` 之后允许 `throws` 和空白，然后必须是 `{`（方法体）或 `;`（抽象/接口方法）
    """
    res = []
    for m in RE_RET_START.finditer(body):
        name = m.group(2)
        i = m.end() - 1          # 指向 '('
        depth, j = 0, i
        while j < len(body):
            c = body[j]
            if c == '(':
                depth += 1
            elif c == ')':
                depth -= 1
                if depth == 0:
                    break
            j += 1
        if depth != 0:
            continue
        # ')' 之后：跳过 throws 声明，找 '{'
        k = j + 1
        tail = body[k:k+400]
        tm = re.match(r"\s*throws\s+[\w\s,\.]*", tail)
        if tm:
            k += tm.end()
        while k < len(body) and body[k] in " \t\r\n":
            k += 1
        if k >= len(body) or body[k] != "{":
            continue
        # 花括号配平找方法体
        depth, e = 0, k
        while e < len(body):
            if body[e] == "{":
                depth += 1
            elif body[e] == "}":
                depth -= 1
                if depth == 0:
                    break
            e += 1
        res.append((name, body[k+1:e]))
    return res


def method_bodies(src):
    """方法体提取。委托给 scan_methods（手写扫描器，见其注释：正则会被嵌套括号截断）。"""
    return scan_methods(src)


def find_type_body(src, cls):
    """取类体（第一个 class 声明之后的花括号块）"""
    m = re.search(r"\b(?:class|interface|enum|record)\s+%s\b" % re.escape(cls), src)
    if not m: return ""
    i = src.find("{", m.end())
    if i < 0: return ""
    depth, j = 0, i
    while j < len(src):
        if src[j] == "{": depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0: return src[i+1:j]
        j += 1
    return src[i:]


# ───────────────── 角色分类 ─────────────────
# ⚠ 角色判定顺序敏感：注解优先于类名后缀。
#   @RestController 类名叫 XxxService 的也有（历史遗留），注解是更强的证据。
#   但 @Service 类名叫 XxxManager 的也是常见的（能力层写成了 Service 注解）——
#   这时类名后缀是更强的证据，因为它指向真实的语义层位。

# 类名后缀 → 角色。顺序 = 优先级从高到低。
# 依据 Spring/Java 生态约定：
#   *Controller   入口层
#   *Scheduler / *Listener / *Consumer / *Handler / *Trigger / *Notifier  入口层（调度/事件触发）
#   *Producer / *Publisher / *Sender  出口层（发消息/发事件）
#   *Repository / *Dao  资源层（碰存储）
#   *Mapper        资源层（MyBatis）
#   *Manager / *Helper / *Builder / *Resolver / *Seeder / *Factory  能力层
#   *Client / *Gateway / *Support  能力层（对外通信的包装）
#   *Service       应用层（业务编排）
#   *Config        横切层
#   *Entity / *DO / *DTO / *VO  横切层（纯数据载体）
SUFFIX_ROLE = [
    ("Controller", "controller"),
    # ⚠ Scheduler 是入口（定时触发）但 Notifier 是**出口**（往外发）——
    #   两者方向相反，绝不能归同一层。
    #   踩坑：Notifier 被归成 L4 入口后，业务 Service 调 Notifier 全被判成
    #   「L3 调 L4 反向依赖」，实测 z-opc 仓产出 6 条假硬错。
    ("Scheduler", "entry"), ("Listener", "entry"), ("Consumer", "entry"),
    ("Handler", "entry"), ("Trigger", "entry"), ("Job", "entry"),
    ("Producer", "producer"), ("Publisher", "producer"), ("Sender", "producer"),
    ("Notifier", "notifier"), ("Dispatcher", "notifier"), ("Broadcaster", "notifier"),
    ("Repository", "repo"), ("Dao", "repo"),
    ("Mapper", "mapper"),
    ("Manager", "capability"), ("Helper", "capability"), ("Builder", "capability"),
    ("Resolver", "capability"), ("Seeder", "capability"), ("Factory", "capability"),
    ("Parser", "capability"), ("Converter", "capability"), ("Checker", "capability"),
    ("Client", "capability"), ("Gateway", "capability"), ("Support", "capability"),
    ("Wrapper", "capability"), ("Adapter", "capability"),
    ("Service", "service"), ("ServiceImpl", "service"),
    ("Config", "config"), ("Configuration", "config"),
    ("Properties", "config"),
    ("Entity", "entity"), ("DO", "entity"), ("DTO", "entity"), ("VO", "entity"),
    ("EntityInfo", "entity"),
]


def suffix_role(cls):
    for suf, role in SUFFIX_ROLE:
        if cls.endswith(suf):
            return role
    return None


def classify(cls, annos, body, imports, whole=""):
    a = set(annos)
    # ⚠ 注解在类体「外面」（@FeignClient 写在 class 关键字之前），
    #   只看花括号内的 body 会漏掉它 —— 跨服务调用就全丢了。
    # ⚠ 但必须按「整个词」匹配：@EnableFeignClients 里也含 "FeignClient" 子串，
    #   用 `in` 判断会把启动类误判成 Feign 客户端（OrderApplication 就中过招）。
    if "FeignClient" in a or re.search(r"\bFeignClient\b", whole):
        return "feign"
    # 存储/资源层：注解与后缀一致，无冲突
    if a & {"Repository"} or cls.endswith("Repository") or cls.endswith("Dao"):
        return "repo"
    if "Mapper" in cls or a & {"Mapper"}:
        return "mapper"
    # 入口层：注解优先
    if a & {"RestController", "Controller"}:
        return "controller"
    if a & {"RestControllerAdvice", "ControllerAdvice"}:
        return "config"
    # 横切层
    if a & {"Configuration"}:
        return "config"
    # ⚠ MyBatis-Plus 实体：@TableName / @TableId / @TableField。
    #   这类类没有 @Entity 注解（那是 JPA 的），只靠类名后缀也认不出
    #   （叫 XxxInfo / XxxRecord / XxxPO 的都有）⇒ 会大量落进 other。
    if a & {"TableName", "TableId", "TableField", "TableLogic"}:
        return "entity"
    # ⚠ 只有 @Override 的类 = 实现了某个接口。它本身没有层位语义，
    #   但按 other → X 归横切层即可（不看它调谁）。
    # ⚠ @JsonIgnoreProperties / @JSONField 是序列化标注的 DTO ⇒ entity
    # 消费/生产：注解明确
    if a & {"KafkaListener", "RabbitListener", "EventListener"}:
        return "entry"
    if a & {"Component", "Service"}:
        # ⚠ 注解只说明「它是个 bean」，不说明它是哪一层。
        #   类名后缀才是层位证据。@Service 类名叫 XxxManager → 能力层。
        sr = suffix_role(cls)
        if sr in ("capability", "entry", "producer", "repo", "mapper", "config",
                  "entity", "notifier"):
            return sr
        if sr in ("service", "controller"):
            return sr
        return "service"
    # 无关键注解：按类名后缀
    sr = suffix_role(cls)
    if sr:
        return sr
    if "Consumer" in cls or "Listener" in cls:
        return "entry"
    if "Producer" in cls or "Publisher" in cls:
        return "producer"
    if a & {"Entity"} or a & {"Document"}:
        return "entity"
    return "other"


# ───────────────── 层位先验（角色 → 层） ─────────────────
# ⚠ 之前用「下游数量」推导层位（service 下游≥2→L3），这是错的：
#   下游数量反映的是「被复用程度」，不是「抽象层次」。
#   实测 z-opc 仓 37 条 up 里绝大多数是 L2→L3，而那些 L3 其实是 Manager/Listener
#   这类能力/入口单元，只是因为被多方调用被误提为 L3。
#   层位必须是**语义先验**（角色/命名约定给出），调用图只用来校验一致性。
ROLE_LAYER = {
    "repo": "L1", "mapper": "L1", "producer": "L1",
    "capability": "L2",
    # ⚠ notifier = 对外广播（WebSocket 推送、消息通知）。
    #   它是**出口**，业务层调它是正常方向 ⇒ L2，不能放 L4。
    "notifier": "L2",
    "service": "L3",
    "controller": "L4", "entry": "L4",
    "config": "X", "entity": "X", "other": "X",
    "feign": "L1", "remote": "L1",
}


# ───────────────── 服务归属识别 ─────────────────
# 原实现只认路径里的 "services/<name>/"（那是那个 GitHub 样本仓的布局）。
# z-opc 业务群是「一个仓多个 maven 模块」的布局，服务边界 = 模块。
# 判据（按可靠性排序）：
#   ① 路径里含 src/main 之前的那一层就是模块名（maven 多模块标准布局）
#   ② 路径里含 services/<name>/（样本仓布局）
#   ③ 都不中 ⇒ 归到仓根（单模块仓）
def detect_service(root, path, pkg):
    parts = os.path.relpath(path, root).replace("\\", "/").split("/")
    # ② services/<name>
    if "services" in parts:
        i = parts.index("services")
        if i + 1 < len(parts):
            return parts[i + 1]
    # ① maven 多模块：<module>/src/main/java/...
    #    从后往前找 "src"，它前面那层就是模块名
    for i, p in enumerate(parts):
        if p == "src" and i > 0:
            return parts[i - 1]
    return "_root"


# ───────────────── 扫描 ─────────────────
def scan(root):
    units = {}
    by_service = defaultdict(list)
    svc_of_pkg = {}          # package 前缀 → service

    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d not in (".git", "target", "build", "node_modules")]
        norm = dirpath.replace("\\", "/")
        # 只取 src/main 下的代码，测试代码不算架构
        if "/src/main/" not in norm + "/":
            continue
        for fn in filenames:
            if fn.endswith(".java"):
                files.append(os.path.join(dirpath, fn))

    for path in files:
        raw = io.open(path, encoding="utf-8", errors="replace").read()
        src = strip_comments(raw)
        pm = RE_PACKAGE.search(src)
        pkg = pm.group(1) if pm else ""
        parts = path.replace("\\", "/").split("/")
        svc = detect_service(root, path, pkg)

        cm = RE_CLASS.search(src)
        if not cm: continue
        cls = cm.group(2)
        # ⚠ 类级注解 = class 关键字**之前**的注解。
        #   把整文件的注解都算成类级是错的：@EventListener / @Scheduled 绝大多数是
        #   方法级注解。混进类级后，一个普通 @Service 类会被判成「入口层」，
        #   连带造出 L3→L4 的假反向依赖。
        cls_head = src[:cm.start()]
        annos = RE_ANNOT.findall(cls_head)
        body = find_type_body(src, cls)
        methods = method_bodies(body)

        # 唯一键：服务 + 包 + 类名（同名类不同服务/不同包必须分得开）
        key = "%s::%s" % (svc, pkg.replace("com.example", "").strip(".") + "." + cls)

        u = {
            "key": key, "svc": svc, "cls": cls, "pkg": pkg,
            "path": os.path.relpath(path, root),
            "role": classify(cls, annos, body, RE_IMPORT.findall(src), src),
            "annos": sorted(set(annos)),
            "imports": RE_IMPORT.findall(src),
            "fields": [], "methods": [], "calls": [], "xsvc": [], "topics": [],
        }

        ftypes = {}
        for typ, name in RE_FIELD.findall(body):
            simple = typ.split("<")[0].split(".")[-1].strip()
            if not simple or simple in ("return", "new", "throw"): continue
            # ⚠ 值类型不是依赖。private final String baseUrl; / private final int timeoutMs = 5000;
            #   这些是配置值，不是注入的协作者。把它们当依赖 ⇒
            #   ① 调用边指向 java.lang.String（仓内找不到 ⇒ 误报 external）
            #   ② 污染依赖表，让「这个类依赖谁」完全失真。
            if simple in VALUE_TYPES: continue
            ftypes[name] = simple
            u["fields"].append({"field": name, "type": simple})

        # ⚠ 方法级触发注解：@EventListener / @Scheduled / @KafkaListener / @RocketMQMessageListener
        #   这类注解说明「这个类是被事件/定时驱动的」，是架构上的**触发源**，
        #   但它不等于「这个类是入口层」——被 @EventListener 触发的通常还是业务服务。
        #   单独记下来，作为评估维度「事件驱动度」的依据。
        #   ⚠ 判据必须用新扫描器（RE_METHOD 会被嵌套括号截断 ⇒ 触发注解也定位不到）。
        method_triggers = []
        for m in RE_TRIGGER_SCAN.finditer(body):
            mhead = body[max(0, m.start() - 400):m.start()]
            for t in TRIGGER_ANNOS:
                if re.search(r"@%s\b" % t, mhead):
                    method_triggers.append(t)
                    break
        if method_triggers:
            u["triggers"] = sorted(set(method_triggers))

        for mname, mbody in methods:
            for mm in RE_CALL.finditer(mbody):
                recv, meth = mm.group(1), mm.group(2)
                if recv in ("this", "super"): continue
                if recv in ftypes:
                    u["calls"].append({"from": mname, "recv": recv,
                                       "type": ftypes[recv], "meth": meth})
        u["methods"] = [{"name": n, "len": len(b)} for n, b in methods]

        # 手写 HTTP 客户端：@Value("${application.config.xxx-url}") + RestTemplate
        # 这类类不是 @FeignClient，但同样是「跨服务出口」，必须归到 remote 角色，
        # 否则它会被当成普通 service，跨服务边全丢。
        vm = RE_VALUE_URL.search(body) or RE_VALUE_URL.search(src)
        if vm and re.search(r"\bRestTemplate\b|\bWebClient\b|\bHttpClient\b", body):
            u["url_prop"] = vm.group(1)
            u["http_client"] = True

        # Kafka 主题
        for tm in re.finditer(r'topics\s*=\s*"([\w\-]+)"', body): u["topics"].append(tm.group(1))
        for tm in re.finditer(r'"([\w\-]+-topic)"', body): u["topics"].append(tm.group(1))
        u["topics"] = sorted(set(u["topics"]))

        units[key] = u
        by_service[svc].append(key)

    return units, by_service


# ───────────────── 服务索引（配置 → 服务归属） ─────────────────
# 跨服务调用有两条路：
#   ① Feign：@FeignClient(name="xxx-service", url="${application.config.xxx-url}")
#   ② 手写 HTTP 客户端：@Value("${application.config.xxx-url}") + RestTemplate
# 要判定「这条边跨到哪个服务」，光看代码不够 —— 得看配置里 xxx-url 指向谁。
# 三条独立证据，交叉验证：
#   a) 配置属性名  xxx-url            → 服务 xxx
#   b) @FeignClient(name="xxx-service")→ 服务 xxx
#   c) URL 路径尾段 /api/v1/xxxs      → 服务 xxx
# 证据之间不一致 ⇒ 这本身就是一条架构缺陷（声明与配置打架）。
RE_YML_PORT = re.compile(r"^\s*port\s*:\s*(\d+)", re.M)
RE_YML_URL = re.compile(r"^\s*([\w-]+-url)\s*:\s*(\S+)", re.M)
RE_YML_APPNAME = re.compile(r"^\s*name\s*:\s*([\w-]+-service)\s*$", re.M)
RE_VALUE_URL = re.compile(r'@Value\(\s*"\$\{application\.config\.([\w-]+-url)\}"\s*\)')
RE_FEIGN_NAME = re.compile(r'@FeignClient\s*\(([^)]*)\)', re.S)
RE_FEIGN_NAME_ATTR = re.compile(r'name\s*=\s*"([\w-]+)"')
RE_FEIGN_URL_ATTR = re.compile(r'url\s*=\s*"\$\{application\.config\.([\w-]+-url)\}"')


def build_service_index(root):
    """扫全仓配置，建立 (配置属性名 → 服务名) 映射。

    依据：application.config.<x>-url 指向某服务的资源路径，
    而 config-server 的 configurations/<svc>-service.yml 里写着该路径。
    """
    # 配置属性 → URL
    prop_url = {}
    # 配置文件名 → 服务名（config-server 的 configurations/<svc>-service.yml）
    svc_files = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in (".git", "target", "build", "node_modules")]
        norm = dirpath.replace("\\", "/")
        for fn in filenames:
            if not fn.endswith((".yml", ".yaml")):
                continue
            path = os.path.join(dirpath, fn)
            txt = io.open(path, encoding="utf-8", errors="replace").read()
            for prop, url in RE_YML_URL.findall(txt):
                prop_url[prop] = url
            if "/configurations/" in norm + "/":
                svc = re.sub(r"\.ya?ml$", "", fn)
                if svc.endswith("-service"):
                    svc_files[svc] = txt
    # 服务 → 资源路径首段（从 controller 的 @RequestMapping 拿，最可靠）
    svc_path = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in (".git", "target", "build", "node_modules")]
        norm = dirpath.replace("\\", "/")
        if "/src/main/java/" not in norm + "/":
            continue
        for fn in filenames:
            if not fn.endswith(".java"):
                continue
            txt = io.open(os.path.join(dirpath, fn), encoding="utf-8", errors="replace").read()
            m = re.search(r'@RequestMapping\(\s*"([^"]*)"', txt)
            if not m:
                continue
            seg = [x for x in m.group(1).split("/") if x]
            if not seg:
                continue
            svc = norm.split("/services/")[-1].split("/")[0] if "/services/" in norm else "?"
            svc_path.setdefault(svc, set()).add(seg[-1].lower())

    def norm_svc(s):
        s = s.lower()
        if s.endswith("-service"):
            s = s[:-len("-service")]
        return s

    prop_svc = {}
    for prop, url in prop_url.items():
        base = prop[:-len("-url")] if prop.endswith("-url") else prop
        cand = {norm_svc(base)}
        m = re.search(r"/api/v\d+/([\w-]+)", url)
        if m:
            cand.add(norm_svc(m.group(1).rstrip("s")))
        hit = None
        for svc, paths in svc_path.items():
            for p in paths:
                if norm_svc(p.rstrip("s")) in {norm_svc(c) for c in cand}:
                    hit = svc
        prop_svc[prop] = hit or base
    return prop_svc


# ───────────────── 组图 ─────────────────
def build(units, by_service, root):
    feign_conflict = []
    # ① 找 Feign 目标服务
    #    ⚠ Feign 接口物理上放在「调用方」服务里（order 服务自带 CustomerClient/PaymentClient/ProductClient），
    #    所以「同服务同名类」这条规则会把跨服务调用误判成同服务调用。
    #    正确做法：先按 @FeignClient(name="xxx-service") 定位接口的真正主人服务，
    #    再把接口挂到那个服务名下，建一条 svc 之间的 xsvc 边。
    feign_of = {}     # 类名 → [(本地key, 目标服务名)]
    feign_owner = {}  # 类名 → 目标服务
    feign_local = {}  # 类名 → 本地副本 key（副本本身不进图）
    prop_svc = build_service_index(root)
    for k, u in units.items():
        if u["role"] != "feign": continue
        raw = io.open(os.path.join(root, u["path"]), encoding="utf-8", errors="replace").read()
        fm = RE_FEIGN_NAME.search(raw)
        declared = None
        url_prop = None
        if fm:
            inner = fm.group(1)
            nm = RE_FEIGN_NAME_ATTR.search(inner)
            if nm:
                declared = nm.group(1).replace("-service", "")
            um = RE_FEIGN_URL_ATTR.search(inner)
            if um:
                url_prop = um.group(1)
        # 目标服务：以配置（url 属性）为准；name 属性只作交叉校验
        target = None
        if url_prop:
            target = prop_svc.get(url_prop)
        if not target:
            target = declared
        feign_of.setdefault(u["cls"], []).append((k, target))
        if target:
            feign_owner[u["cls"]] = target
            feign_local[u["cls"]] = k
            # ⚠ 声明与配置打架：@FeignClient(name="product-service") 但 url 指向 payment
            #    这是上游仓的真实 bug（PaymentClient 复制粘贴），抓出来当架构缺陷报。
            #    注意：主体记的是本地副本 key，它随后会被剔出图 —— 影子单元建好后
            #    再把 f 改指向影子（影子在图上，点击才能定位过去）。
            if declared and url_prop and declared != target:
                feign_conflict.append({
                    "kind": "feign_conflict", "cls": u["cls"], "owner": k,
                    "declared": declared, "actual": target, "url_prop": url_prop,
                    "path": u["path"],
                })

    # ② 影子单元（跨服务出口）
    #    Feign 接口 / 手写 HTTP 客户端都住在调用方服务里，但它们代表的是「另一个服务的入口」。
    #    在主人服务下造一个影子单元（target::remote.XxxClient），调用边指向它，
    #    这样跨服务调用才能在图上画成一条真的服务→服务的线，而不是缩在本地。
    remote_owner = {}   # 本地出口key → 影子key
    shadow_of = {}      # 类名 → 影子key
    feign_local_keys = set(feign_local.values())
    for k, u in list(units.items()):
        is_feign = u["role"] == "feign"
        is_http = u.get("http_client")
        if not (is_feign or is_http):
            continue
        if is_feign:
            target = feign_owner.get(u["cls"])
        else:
            target = prop_svc.get(u.get("url_prop", ""))
        if not target or target == u["svc"]:
            continue
        skey = "%s::remote.%s" % (target, u["cls"])
        if skey not in units:
            units[skey] = {
                "key": skey, "svc": target, "cls": u["cls"], "pkg": u["pkg"],
                "path": u["path"], "role": "remote",
                "annos": ["FeignClient"] if is_feign else ["HttpClient"],
                "imports": [], "fields": [], "methods": [], "calls": [],
                "xsvc": [], "topics": [], "remote_of": k,
            }
            by_service[target].append(skey)
        remote_owner[k] = skey
        shadow_of[u["cls"]] = skey
        # 本地出口本身是「通道」，不进图；影子单元已经表达了被调方
        feign_local_keys.add(k)

    edges = []
    # 影子单元集合：跨服务出口的替身，不是本仓真实类，不能作为同模块依赖目标
    shadow_keys = {k for k in units if "::remote." in k}
    # ⚠ all_keys 必须在影子单元建好之后取，否则跨模块回落匹配会把调用边指向影子，
    #   变成「本服务调本服务」的错误边。
    all_keys = list(units.keys())
    # 同名类歧义记录（仓内多份同名类）
    ambiguous = []
    # 手写 HTTP 客户端（类名 → url 配置属性）
    http_clients = {u["cls"]: u.get("url_prop", "") for u in units.values() if u.get("http_client")}
    for k, u in list(units.items()):
        for c in u["calls"]:
            ctype = c["type"]
            # 优先：这个类型是跨服务出口（Feign 接口 / 手写 HTTP 客户端）⇒ 跨服务边
            if ctype in feign_owner or ctype in http_clients:
                tgt = feign_owner.get(ctype) or prop_svc.get(http_clients.get(ctype, ""))
                if tgt and tgt != u["svc"]:
                    skey = shadow_of.get(ctype)
                    if skey:
                        edges.append({"f": k, "t": skey, "kind": "xsvc", "via": c["meth"]})
                    else:
                        owners = [k2 for k2 in by_service.get(tgt, [])
                                  if k2.endswith("." + ctype)
                                  or k2.endswith("." + ctype + "Controller")
                                  or k2.endswith("." + ctype + "Service")]
                        if owners:
                            edges.append({"f": k, "t": owners[0], "kind": "xsvc", "via": c["meth"]})
                continue
            # 同服务内匹配（优先，最精确）
            cand = [k2 for k2 in by_service.get(u["svc"], [])
                    if k2.endswith("." + ctype) and k2 != k]
            if cand:
                edges.append({"f": k, "t": cand[0], "kind": "call", "via": c["meth"]})
                continue
            # ⚠ 跨模块匹配（同一仓内，不同 maven 模块）。
            #   这是最常见的依赖方向：web/starter 模块调 core 模块的 Service。
            #   只在同模块内找 ⇒ 这些边全丢 ⇒ 大量 Controller 被误判「孤立件」
            #   （实测 z-opc 仓 140/185 的孤立件是这个原因）。
            #   消歧：同名类在仓内多份存在时，按包名最近者优先；
            #   仍多份 ⇒ 取第一个并记「同名歧义」。
            cand = [k2 for k2 in all_keys
                    if k2.endswith("." + ctype) and k2 != k
                    and k2 not in feign_local_keys
                    and k2 not in shadow_keys
                    ]
            if cand:
                cand.sort(key=lambda kk: (
                    -len(os.path.commonprefix([units[kk]["pkg"], u["pkg"]])),
                    units[kk]["pkg"], kk))
                edges.append({"f": k, "t": cand[0], "kind": "call", "via": c["meth"]})
                if len(cand) > 1:
                    ambiguous.append({"f": k, "t": cand[0], "type": ctype,
                                      "n": len(cand)})

    # ② Kafka：producer → consumer
    prod_of_topic, cons_of_topic = defaultdict(list), defaultdict(list)
    for k, u in units.items():
        for t in u["topics"]:
            if u["role"] == "producer": prod_of_topic[t].append(k)
            elif u["role"] == "consumer": cons_of_topic[t].append(k)
    for t, ps in prod_of_topic.items():
        for c in cons_of_topic.get(t, []):
            for p in ps:
                edges.append({"f": p, "t": c, "kind": "kafka", "via": t})

    # 去重
    seen, uniq = set(), []
    for e in edges:
        sig = (e["f"], e["t"], e["kind"])
        if sig in seen: continue
        seen.add(sig); uniq.append(e)

    # ③ 层位推导
    # ⚠ 层位 = 角色先验（语义），调用图只做**一致性修正**，不做主判定。
    #   历史教训：用「下游数量」定层（service 下游≥2→L3）会产出 37 条假 up，
    #   因为被多方调用的 Manager/Listener 被误提为 L3。
    #   修正规则只有一条：**被 L4 入口直接调用的 L3 应用单元，降为 L2 能力层**。
    #   （入口层直接调的东西若还去调别的 L3，说明它其实是能力层不是编排层。）
    role_of = {k: u["role"] for k, u in units.items()}
    out_e, in_e = defaultdict(list), defaultdict(list)
    for e in uniq:
        out_e[e["f"]].append(e); in_e[e["t"]].append(e)

    layer = {k: ROLE_LAYER.get(u["role"], "X") for k, u in units.items()}

    # ⚠ 这里**不做**任何调用图驱动的层位改写。
    #   历史教训：曾用「入口直调的 service 降一层」做一致性修正，结果
    #   Controller→Service 变成 L4→L2，判据判成「跳层」——凭空造出大量假缺陷。
    #   层位是**语义契约**（角色先验），不由调用图反推；调用图只用来判违例。

    # Feign 本地副本不进图：它是「调用通道」，影子单元已经表达了被调方
    for k in feign_local_keys:
        units.pop(k, None)
        layer.pop(k, None)
        for lst in by_service.values():
            if k in lst: lst.remove(k)

    # ④ 自检
    viol = []
    LN = {"L1": 1, "L2": 2, "L3": 3, "L4": 4}
    # 资源层角色：它们的依赖方向是「直连合法」的（Service→Mapper 是 Spring 标准）
    RESOURCE_ROLES = ("repo", "mapper", "producer", "feign", "remote")
    # ⚠ 通道类：纯粹的对外出入口（HTTP 客户端 / 网关 / 集成 SDK）。
    #   它们出现在调用图上只是「数据进出」，不是「层间依赖」——
    #   一个钉钉 Stream 客户端去调业务 Service，是**正常集成**，不是架构倒挂。
    #   判据：类名以 Client/Gateway/Api/Http/Rpc 结尾，且不叫 Service。
    CHANNEL_ROLE = "capability"
    def is_channel(k):
        u = units[k]
        if u["role"] != CHANNEL_ROLE: return False
        cls = u["cls"]
        if cls.endswith("Service") or cls.endswith("ServiceImpl"): return False
        return bool(re.search(r"(Client|Gateway|Api|Http|Rpc|Proxy)$", cls))

    for e in uniq:
        lf, lt = layer.get(e["f"]), layer.get(e["t"])
        # 跨服务调用和消息投递是「服务边界」，不是层间依赖 ⇒ 不参与层位自检
        if e["kind"] in ("xsvc", "kafka"):
            continue
        # 通道类作为调用方 ⇒ 不参与层位自检（它是数据出入口，不是层内依赖）
        if is_channel(e["f"]):
            continue
        if lf in LN and lt in LN:
            if LN[lt] > LN[lf]:
                # 反向依赖：低层（数字小=靠下）去调高层。
                # ⚠ 必须按「方向」分级，因为**可信度不同**：
                #   L1→L2/L3/L4 资源层反向依赖业务  = 硬错误（存储层不该知道业务）
                #   L3→L4     业务层反过来依赖入口   = 硬错误（循环依赖的信号）
                #   L2→L3     能力层调应用层         = 软信号（依赖命名约定：
                #                        Builder 调 Service 到底算不算倒挂，
                #                        不同团队口径不同 ⇒ 只作提示不作扣分）
                hard = (lf == "L1") or (lf == "L3" and lt == "L4")
                viol.append({"level": "err" if hard else "info", "kind": "up",
                             "msg": "反向依赖：%s(%s) 调了更靠上的 %s(%s)" %
                                    (units[e["f"]]["cls"], lf, units[e["t"]]["cls"], lt),
                             "f": e["f"], "t": e["t"]})
            elif LN[lf] - LN[lt] >= 2:
                # ⚠ 「跳层」的定义要精确，否则全是假阳性。
                #   实测踩坑：曾把 L4(入口) → L2(能力) 判成跳层，产出 32 条假缺陷。
                #   但 Controller 直接调能力层是**标准做法**（Application Service 薄是好事），
                #   中间**不需要**存在 L3。
                #   真跳层只有一种：**编排/能力层绕过能力层直接摸存储**，
                #   即 L3 → L1（业务编排层直接写 SQL 语义，绕过领域能力封装）。
                if lf == "L3" and lt == "L1":
                    tgt_role = role_of.get(e["t"])
                    if tgt_role not in RESOURCE_ROLES:
                        viol.append({"level": "warn", "kind": "skip",
                                     "msg": "跳层：%s(%s) 直连 %s(%s)，绕过能力层" %
                                            (units[e["f"]]["cls"], lf, units[e["t"]]["cls"], lt),
                                     "f": e["f"], "t": e["t"]})
                elif lf == "L4" and lt == "L1":
                    # 入口层直达存储：Controller 直接摸 Mapper/Repository，
                    # 业务规则写在了接口层。
                    # ⚠ 必须区分 Controller 与 Scheduler/Listener：
                    #   Controller 直连 Mapper = 业务规则泄漏到接口层（硬缺陷）
                    #   Scheduler/Listener 直连 Mapper = 运维补偿/对账任务，
                    #     直连存储是**合理**的（要绕过业务层做数据修正）⇒ 只记 info。
                    frole = role_of.get(e["f"])
                    if frole == "controller":
                        viol.append({"level": "err", "kind": "bypass",
                                     "msg": "入口层直达存储：Controller %s(%s) 直接调 %s(%s)，"
                                            "业务规则写在了接口层" %
                                            (units[e["f"]]["cls"], lf, units[e["t"]]["cls"], lt),
                                     "f": e["f"], "t": e["t"]})
                    else:
                        viol.append({"level": "info", "kind": "sched_bypass",
                                     "msg": "调度/事件源直连存储：%s(%s) 直接调 %s(%s)"
                                            "（运维补偿类，核对是否为合理绕过）" %
                                            (units[e["f"]]["cls"], lf, units[e["t"]]["cls"], lt),
                                     "f": e["f"], "t": e["t"]})
        if e["kind"] == "xsvc":
            sf = units[e["f"]]["svc"]; st = units[e["t"]]["svc"]
            if sf == st:
                viol.append({"level": "warn", "kind": "xsame",
                             "msg": "跨服务边其实同服务：%s → %s" % (units[e["f"]]["cls"], units[e["t"]]["cls"]),
                             "f": e["f"], "t": e["t"]})

    # 孤立件
    # ⚠ 判据必须区分「真孤立」和「依赖在仓外」。
    #   边只在**本仓内**按类名匹配 —— 注入的 JobInfoService 若来自另一个 Maven 仓，
    #   本仓就找不到它，于是 Controller 看起来毫无下游。
    #   实测 z-opc 仓 140 个 Controller 因此被误报孤立（占全部孤立件的 76%）。
    #   修法：先算出「本仓里找不到的被调用类型」，有这类调用就不算孤立，
    #   而归类为「外部依赖」（external）—— 这本身是有用信息，不是缺陷。
    #
    # ⚠ 还要排除「纯静态工具类」（Util/Support/Holder + private 构造器 + 无实例字段）：
    #   ScanWindowSupport 这类类不注入任何东西是**设计使然**，
    #   被别人 static import 使用，不参与调用图 —— 不是架构债。
    #   实测 z-team 114 个 orphan 里 46 个 capability 角色多数是这类。
    local_types = {u["cls"] for u in units.values()}
    for k, u in units.items():
        if layer[k] == "X": continue
        if out_e.get(k) or in_e.get(k): continue
        # 纯静态工具类：有 private 构造器（或类本身 final）+ 无实例字段 ⇒ 豁免
        raw_src = ""
        try:
            raw_src = io.open(os.path.join(root, u["path"]), encoding="utf-8",
                              errors="replace").read()
        except Exception:
            pass
        has_private_ctor = re.search(r"private\s+\w+\s*\(\s*\)", raw_src) is not None
        no_instance_fields = not u["fields"]
        is_static_util = (has_private_ctor and no_instance_fields) or \
                         u["cls"].endswith(("Util", "Utils", "Consts", "Constants"))
        if is_static_util:
            continue
        ext = sorted({c["type"] for c in u["calls"]
                      if c["type"] and c["type"] not in local_types})
        if ext:
            viol.append({"level": "info", "kind": "external",
                         "msg": "外部依赖：%s(%s) 调用了本仓不存在的 %s" %
                                (u["cls"], layer[k], "、".join(ext[:3]) +
                                 ("等 %d 个" % len(ext) if len(ext) > 3 else "")),
                         "f": k, "t": None})
        else:
            viol.append({"level": "warn", "kind": "orphan",
                         "msg": "孤立件：%s(%s) 在调用图上没有上下游" % (u["cls"], layer[k]),
                         "f": k, "t": None})

    # 声明与配置打架（Feign name 与 url 指向不同服务）
    # ⚠ f 必须指向图上存在的单元。影子单元（target::remote.XxxClient）代表被调方，
    #   而「声明写错了」这个缺陷恰恰发生在被调方那一侧 ⇒ 指影子才对。
    #   若指本地副本，它已被剔出图，画布点击会找不到节点。
    for c in feign_conflict:
        subject = shadow_of.get(c["cls"]) or c["owner"]
        viol.append({"level": "err", "kind": "conflict",
                     "msg": "跨服务声明与配置打架：%s 的 @FeignClient(name=%s-service) "
                            "但 url 属性 %s 实际指向 %s-service" %
                            (c["cls"], c["declared"], c["url_prop"], c["actual"]),
                     "f": subject, "t": None})

    return uniq, layer, viol, role_of


# ───────────────── Maven 模块依赖图 ─────────────────
# ⚠ 这是**完全客观**的架构指标：不依赖任何命名约定或人工判断。
#   Maven 模块依赖有向图如果出现环 ⇒ 编译顺序无法确定 ⇒ 硬缺陷。
#   圈复杂度/扇入扇出也是从这张图上算的。
RE_POM_ARTIFACT = re.compile(r"<artifactId>\s*([^<]+?)\s*</artifactId>")
RE_POM_GROUP    = re.compile(r"<groupId>\s*([^<]+?)\s*</groupId>")
RE_POM_MODULE   = re.compile(r"<module>\s*([^<]+?)\s*</module>")
RE_POM_DEP      = re.compile(r"<dependency>(.*?)</dependency>", re.S)
RE_POM_DESC     = re.compile(r"<description>(.*?)</description>", re.S)

# 自有 groupId 前缀（内部依赖 = 架构内部边）
OWN_GROUPS = ("com.c2f.galaxy", "com.c2f.boot", "com.c2f", "com.zifang", "io.github.yuku123")

# ⚠ 模块角色约定（**从 pom 的 <description> 里读**，不靠猜）。
#   z-opc 仓的 pom 明确写了「web 只做暴露，业务在 core，启动装配在 starter」——
#   这是仓里已有的显式架构契约，比任何启发式都可靠。
#
# ⚠ 但关键词匹配必须**精确**。踩过的坑：
#   future-team-common 的描述是「原子能力接口包（平台能力契约）」——
#   含"接口"二字，被朴素关键词判成 web(暴露层) ⇒ 造出
#   「core 依赖 web」这种假倒挂。实测 10 条 modrole 里 5 条是这类误报。
#   ⇒ 规则必须：**先看 artifactId 后缀**（结构化，最可靠），
#     后缀缺失才用 description，且 description 用**强特征词**（整词/短语）。
#
# 角色语义：
#   api     契约/接口/SPI 包 —— 只定义接口，被别人依赖
#   core    业务实现 —— 依赖 api
#   web     暴露层（HTTP 入口）
#   starter 装配层（把各件组装起来）
MOD_ROLE_HINT = [
    # 强特征（短语级，误报率低）
    (("暴露层", "http 入口", "web 层", "对外接口", "控制器", "接入层"), "web"),
    (("业务实现", "领域实现", "core 模块", "核心业务", "业务编排"), "core"),
    (("装配", "启动器", "自动配置", "autoconfiguration", "组装"), "starter"),
    (("契约包", "接口包", "spi", "扩展协议", "协议包", "常量包"), "api"),
]


def infer_module_role(text, artifact):
    """判定 maven 模块的架构角色。

    优先级：artifactId 后缀 > description 强特征 > description 弱特征 > unknown
    """
    a = artifact.lower()
    # ① artifactId 后缀 —— 最可靠的结构化信号
    if a.endswith("-web") or a.endswith("-rest"):
        return "web"
    if a.endswith("-core"):
        return "core"
    if a.endswith("-starter") or a.endswith("-boot"):
        return "starter"
    if a.endswith("-api") or a.endswith("-sdk") or a.endswith("-common") \
       or a.endswith("-contract") or a.endswith("-spi") or a.endswith("-facade"):
        return "api"
    # ② description 强特征
    t = (text or "").lower()
    if t:
        for keys, role in MOD_ROLE_HINT:
            for k in keys:
                if k in t:
                    return role
    return "unknown"


def scan_maven_modules(root):
    """扫出 (模块artifactId → {内部依赖artifactId}) 的有向图。

    只把 groupId 属于自有域（com.zifang / io.github.yuku123 等）的依赖算作「内部边」。
    外部依赖（三方库）不参与 —— 它们不构成模块间的循环。
    """
    # 先收集本仓所有模块的 artifactId（用于判定某个依赖是内部还是外部）
    own = set()
    poms = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d not in (".git", "target", "build", "node_modules")]
        if "pom.xml" not in filenames:
            continue
        p = os.path.join(dirpath, "pom.xml")
        try:
            txt = io.open(p, encoding="utf-8", errors="replace").read()
        except Exception:
            continue
        # 去掉 XML 注释（注释里可能有伪 dependency）
        txt = re.sub(r"<!--.*?-->", "", txt, flags=re.S)
        poms.append((dirpath, txt))
        # artifactId 可能是父 pom 的第一个，也可能是本模块的（parent 在前）
        am = RE_POM_ARTIFACT.search(txt)
        if am:
            own.add(am.group(1))
        for mm in RE_POM_MODULE.finditer(txt):
            own.add(mm.group(1).strip())
    # parent 里的 artifactId 不是本模块的，需要按 <parent> 块剔除
    graph = {}
    roles = {}
    parents = set()
    for dirpath, txt in poms:
        # 取本模块自己的 artifactId：跳过 <parent>…</parent> 块
        stripped = re.sub(r"<parent>.*?</parent>", "", txt, flags=re.S)
        am = RE_POM_ARTIFACT.search(stripped)
        if not am:
            continue
        me = am.group(1)
        # ⚠ 父 pom（<packaging>pom</packaging>）只是聚合声明，不是架构单元。
        #   它天然依赖所有子模块 ⇒ 若参与角色检查，必然报一堆假倒挂。
        #   实测 z-audit（父 pom artifactId=z-audit）被判成 api ⇒ 报 3 条假违例。
        if re.search(r"<packaging>\s*pom\s*</packaging>", stripped):
            parents.add(me)
            continue
        deps = set()
        for dm in RE_POM_DEP.finditer(txt):
            block = dm.group(1)
            ga = RE_POM_GROUP.search(block)
            ar = RE_POM_ARTIFACT.search(block)
            if not ar:
                continue
            g = ga.group(1) if ga else ""
            if g.startswith(OWN_GROUPS):
                deps.add(ar.group(1))
        graph[me] = {d for d in deps if d in own and d != me}
        dm = RE_POM_DESC.search(stripped)
        roles[me] = infer_module_role(dm.group(1) if dm else None, me)
    return graph, roles


def find_module_cycles(graph):
    """找出模块依赖环（返回若干条环路径）。"""
    cycles = []
    state = {}   # 0=未访问 1=在栈上 2=已完成
    stack = []

    def dfs(n):
        state[n] = 1
        stack.append(n)
        for m in sorted(graph.get(n, ())):
            if state.get(m, 0) == 1:
                i = stack.index(m)
                cycles.append(stack[i:] + [m])
            elif state.get(m, 0) == 0:
                dfs(m)
        stack.pop()
        state[n] = 2

    for n in sorted(graph):
        if state.get(n, 0) == 0:
            dfs(n)
    return cycles


def module_role_violations(mgraph, mroles):
    """模块角色契约违例（基于 pom description 里声明的分层约定）。

    ⚠ 契约来自仓里自己写的 pom description，不是外部猜测 ⇒ 违例即为「自己说了没做到」。
    ⚠ 这段逻辑**必须**与 batch_extract.py 共用一份 —— 曾因两处各写一遍而漂移。
    """
    out = []
    ALLOWED = {("core", "api"), ("web", "core"), ("web", "api"),
               ("starter", "core"), ("starter", "web"), ("starter", "api"),
               ("api", "api"),
               # ⚠ web → starter 是**正常**的：web 模块靠 starter 完成装配。
               #   实测五仓（z-audit/z-sense/z-watermark…）全部命中这一条 ⇒ 是规则漏写，不是缺陷。
               ("web", "starter")}
    for m, deps in mgraph.items():
        r = mroles.get(m, "unknown")
        if r == "unknown":
            continue
        for d in deps:
            rd = mroles.get(d, "unknown")
            if rd == "unknown" or r == rd:
                continue
            if (r, rd) not in ALLOWED:
                out.append({"level": "err", "kind": "modrole",
                            "msg": "模块角色倒挂：%s(%s) 依赖了 %s(%s)" % (m, r, d, rd),
                            "f": None, "t": None, "mod": m, "mod_dep": d})
    return out


def main():
    if len(sys.argv) < 2:
        print("用法: extract_java_arch.py <repo_root>", file=sys.stderr); sys.exit(2)
    root = sys.argv[1]
    units, by_service = scan(root)
    edges, layer, viol, role_of = build(units, by_service, root)

    # Maven 模块图（客观指标）
    mgraph, mroles = scan_maven_modules(root)
    mcycles = find_module_cycles(mgraph)
    for cyc in mcycles:
        viol.append({"level": "err", "kind": "cycle",
                     "msg": "模块依赖环：%s" % " → ".join(cyc),
                     "f": None, "t": None, "cycle": cyc})

    # 模块角色契约违例（基于 pom description 里声明的分层约定）
    viol.extend(module_role_violations(mgraph, mroles))

    out = {
        "root": root,
        "services": sorted(by_service),
        "units": {}, "layers": layer, "edges": edges, "violations": viol,
        "by_service": {s: by_service[s] for s in by_service},
        "modules": {k: sorted(v) for k, v in mgraph.items()},
        "module_roles": mroles,
    }
    for k, u in units.items():
        out["units"][k] = {
            "svc": u["svc"], "cls": u["cls"], "role": u["role"], "layer": layer[k],
            "annos": u["annos"], "path": u["path"],
            "fields": u["fields"], "methods": u["methods"],
            "calls": u["calls"], "topics": u["topics"],
        }
    json.dump(out, sys.stdout, ensure_ascii=False, indent=1)


if __name__ == "__main__":
    main()
