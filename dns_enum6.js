/**
 * Surge 节点域名枚举 + 自动应用 v6
 * 流程: 逐节点 [清缓存 -> identifier 探针 -> 读缓存] 归属出节点服务器域名,
 *       生成 [Host] server: 指派行, 再经 /v1/profiles/section 接口把指派块
 *       自动写入当前配置的 [Host] 段(带标记, 重跑只替换本工具的块, 不动其他行),
 *       Surge 校验整份配置后自动重载生效。全程无需手动编辑配置。
 * 专用 DNS 服务器由模块参数 doh1/doh2/doh3 配置(模块设置里可改, 留空跳过),
 *       未传参或全空时回退到脚本内置默认值。
 * 若配置为托管/只读导致写入被拒, 面板会显示原因, 生成的指派行仍存于本地存储。
 */

const MAP_KEY = "dns_enum_map";
const BLOCK_KEY = "dns_enum_host_block";
const PROBE_URL = "http://cp.cloudflare.com/generate_204";
const PROBE_TIMEOUT_SEC = 3;
const TIME_BUDGET_MS = 200000;
const DEFAULT_DOH_SERVERS = [
    "https://radar.l9oauy.com:34683/dns-query/1dbbdec9-5627-41a2-bfb8-b195af6544c6",
    "https://8.163.85.149:44443/dns-query/1dbbdec9-5627-41a2-bfb8-b195af6544c6",
    "https://23.146.72.61:44443/dns-query/1dbbdec9-5627-41a2-bfb8-b195af6544c6"
];

function resolveDohServers() {
    const fromArgs = [];
    if (typeof $argument !== "undefined" && $argument) {
        const text = String($argument);
        for (const part of text.split("&")) {
            const eq = part.indexOf("=");
            if (eq < 0) continue;
            const key = part.slice(0, eq).trim();
            const value = part.slice(eq + 1).trim();
            if ((key === "doh1" || key === "doh2" || key === "doh3") && value) {
                fromArgs.push(value);
            }
        }
    }
    if (fromArgs.length > 0) return { servers: fromArgs, custom: true };
    return { servers: DEFAULT_DOH_SERVERS.slice(), custom: false };
}

const DOH_CONFIG = resolveDohServers();
const DOH_SERVERS = DOH_CONFIG.servers;
const MIN_SUFFIX_COUNT = 2;
const MAX_PANEL_DOMAINS = 30;
const MARK_BEGIN = "# >>> proxy-dns-auto >>>";
const MARK_END = "# <<< proxy-dns-auto <<<";

const DENY_EXACT = new Set([
    "cp.cloudflare.com",
    "connectivitycheck.platform.hicloud.com",
    "connectivitycheck.gstatic.com",
    "www.gstatic.com",
    "myip.ipip.net",
    "forge.speedtest.cn",
    "ip-api.com",
    "api.ip.sb",
    "6.ipw.cn",
    "api6.ipify.org",
    "api.ipify.org",
    "ipv6.icanhazip.com",
    "captive.apple.com",
    "dns.google",
    "cloudflare-dns.com",
    "radar.l9oauy.com",
    "doh.pub",
    "dns.alidns.com",
    "one.one.one.one",
    "github.com",
    "raw.githubusercontent.com",
    "script-hub.de5.net",
    "localhost"
]);

const DENY_SUFFIX = [
    ".apple.com",
    ".icloud.com",
    ".icloud.com.cn",
    ".cdn-apple.com",
    ".mzstatic.com",
    ".googleapis.com",
    ".gstatic.com",
    ".whatsapp.net",
    ".facebook.com",
    ".tailscale.com",
    ".githubusercontent.com",
    ".de5.net",
    ".local"
];

function httpApiAsync(method, path, body = {}) {
    return new Promise((resolve) => {
        $httpAPI(method, path, body, (res) => resolve(res || {}));
    });
}

function formatTimeNow() {
    const now = new Date();
    const hh = String(now.getHours()).padStart(2, "0");
    const mm = String(now.getMinutes()).padStart(2, "0");
    const ss = String(now.getSeconds()).padStart(2, "0");
    return `${hh}:${mm}:${ss}`;
}

function isIpLike(text) {
    return /^[0-9.]+$/.test(text) || text.includes(":");
}

function isDenied(domain) {
    if (DENY_EXACT.has(domain)) return true;
    return DENY_SUFFIX.some((suffix) => domain.endsWith(suffix));
}

function suffixOf(domain, labels) {
    const parts = domain.split(".").filter(Boolean);
    if (parts.length <= labels) return domain;
    return parts.slice(parts.length - labels).join(".");
}

function loadMap() {
    try {
        const raw = $persistentStore.read(MAP_KEY);
        if (raw) {
            const parsed = JSON.parse(raw);
            if (parsed && typeof parsed === "object") return parsed;
        }
    } catch (_) {}
    return {};
}

async function readCacheDomains() {
    const res = await httpApiAsync("GET", "/v1/dns");
    const cache = res && Array.isArray(res.dnsCache) ? res.dnsCache : [];
    const domains = [];
    for (const entry of cache) {
        if (entry && typeof entry.domain === "string") {
            const domain = entry.domain.trim().toLowerCase();
            if (domain && !isIpLike(domain) && !isDenied(domain)) {
                domains.push(domain);
            }
        }
    }
    return domains;
}

function probeOnce(identifier) {
    return new Promise((resolve) => {
        let settled = false;
        const finish = () => {
            if (!settled) {
                settled = true;
                resolve(true);
            }
        };
        try {
            setTimeout(finish, (PROBE_TIMEOUT_SEC + 2) * 1000);
        } catch (_) {}
        $httpClient.get({ url: PROBE_URL, timeout: PROBE_TIMEOUT_SEC, policy: identifier }, () => finish());
    });
}

function buildHostLines(distinctDomains) {
    const cluster2 = new Map();
    for (const domain of distinctDomains) {
        const s2 = suffixOf(domain, 2);
        cluster2.set(s2, (cluster2.get(s2) || 0) + 1);
    }
    const serverList = DOH_SERVERS.join(", ");
    const hostLines = [];
    const suffixes = Array.from(cluster2.entries()).sort((a, b) => b[1] - a[1]);
    for (const [suffix, count] of suffixes) {
        if (count >= MIN_SUFFIX_COUNT) {
            hostLines.push(`*.${suffix} = server:${serverList}`);
        }
    }
    for (const domain of distinctDomains) {
        if ((cluster2.get(suffixOf(domain, 2)) || 0) < MIN_SUFFIX_COUNT) {
            hostLines.push(`${domain} = server:${serverList}`);
        }
    }
    return hostLines;
}

function stripAutoBlock(content) {
    const linesArr = content.split("\n");
    const kept = [];
    let inBlock = false;
    for (const line of linesArr) {
        const trimmed = line.trim();
        if (trimmed === MARK_BEGIN) {
            inBlock = true;
            continue;
        }
        if (trimmed === MARK_END) {
            inBlock = false;
            continue;
        }
        if (!inBlock) kept.push(line);
    }
    while (kept.length > 0 && kept[kept.length - 1].trim() === "") kept.pop();
    return kept.join("\n");
}

async function applyToProfile(hostLines) {
    if (hostLines.length === 0) {
        return { ok: false, reason: "没有可应用的指派行" };
    }
    const blockLines = [MARK_BEGIN, `# 自动生成 ${formatTimeNow()}, 来源: 节点域名枚举`, ...hostLines, MARK_END];
    const getRes = await httpApiAsync("GET", "/v1/profiles/section?name=Host");
    let oldContent = "";
    let revision = undefined;
    if (getRes && typeof getRes.content === "string") {
        oldContent = getRes.content;
        if (typeof getRes.revision === "string") revision = getRes.revision;
    } else if (getRes && getRes.error) {
        oldContent = "";
        revision = undefined;
    }
    const cleaned = stripAutoBlock(oldContent);
    const newContent = (cleaned ? cleaned + "\n" : "") + blockLines.join("\n");
    const body = { name: "Host", content: newContent };
    if (revision) body.revision = revision;
    const postRes = await httpApiAsync("POST", "/v1/profiles/section", body);
    if (postRes && postRes.error) {
        return { ok: false, reason: String(postRes.error) };
    }
    await httpApiAsync("POST", "/v1/dns/flush", {});
    return { ok: true, reason: "" };
}

async function main() {
    const lines = [];
    try {
        const policiesRes = await httpApiAsync("GET", "/v1/policies?include_external=true");
        const external = policiesRes && Array.isArray(policiesRes["external-policies"]) ? policiesRes["external-policies"] : [];

        const mapping = loadMap();
        let ipOnly = 0;
        let probed = 0;
        let budgetHit = false;
        const startedAt = Date.now();
        for (const item of external) {
            if (Date.now() - startedAt > TIME_BUDGET_MS) {
                budgetHit = true;
                break;
            }
            const name = item && typeof item.name === "string" ? item.name : "";
            const identifier = item && typeof item.identifier === "string" ? item.identifier : "";
            if (!identifier) continue;
            await httpApiAsync("POST", "/v1/dns/flush", {});
            await probeOnce(identifier);
            const domains = await readCacheDomains();
            probed += 1;
            if (domains.length === 0) {
                ipOnly += 1;
                if (name && !mapping[name]) mapping[name] = [];
            } else if (name) {
                const merged = new Set(mapping[name] || []);
                for (const domain of domains) merged.add(domain);
                mapping[name] = Array.from(merged).sort();
            }
        }
        try {
            $persistentStore.write(JSON.stringify(mapping), MAP_KEY);
        } catch (_) {}

        const domainNodes = new Map();
        for (const [node, domains] of Object.entries(mapping)) {
            for (const domain of domains) {
                if (!domainNodes.has(domain)) domainNodes.set(domain, []);
                domainNodes.get(domain).push(node);
            }
        }
        const distinctDomains = Array.from(domainNodes.keys()).sort();
        const hostLines = buildHostLines(distinctDomains);
        try {
            $persistentStore.write(hostLines.join("\n"), BLOCK_KEY);
        } catch (_) {}

        const applied = await applyToProfile(hostLines);

        lines.push(`外部节点: ${external.length} 个, 已逐个归属探针: ${probed} 个`);
        if (budgetHit) {
            lines.push("⏱ 本次时间预算内未探完(失效节点探针较慢), 已先用已探结果应用; 可再点一次补齐");
        }
        lines.push(`无域名节点(疑似纯IP): ${ipOnly} 个`);
        lines.push(`不同节点域名: ${distinctDomains.length} 个`);
        if (distinctDomains.length > 0) {
            lines.push("节点域名清单 (域名 ← 节点数):");
            for (const domain of distinctDomains.slice(0, MAX_PANEL_DOMAINS)) {
                lines.push(`${domain} ← ${domainNodes.get(domain).length}`);
            }
            if (distinctDomains.length > MAX_PANEL_DOMAINS) {
                lines.push(`...其余 ${distinctDomains.length - MAX_PANEL_DOMAINS} 个见存储`);
            }
        }
        lines.push(`专用DNS: ${DOH_SERVERS.length} 台 (${DOH_CONFIG.custom ? "模块参数自定义" : "内置默认"})`);
        if (applied.ok) {
            lines.push(`✅ 已自动应用: ${hostLines.length} 条指派已写入配置 [Host] 段并重载生效`);
        } else {
            lines.push(`⚠️ 自动应用失败: ${applied.reason}`);
            lines.push("指派行已存本地, 可改用 proxy_dns 模块兜底");
        }
        lines.push(`检查时间: ${formatTimeNow()}`);
        $done({
            title: `节点域名枚举v6 (${formatTimeNow()})`,
            content: lines.join("\n"),
            icon: "list.bullet.indent",
            "icon-color": "#34C759"
        });
    } catch (err) {
        $done({
            title: `节点域名枚举异常 (${formatTimeNow()})`,
            content: `执行失败: ${String(err)}`,
            icon: "exclamationmark.triangle.fill",
            "icon-color": "#FF3B30"
        });
    }
}

main();
