/**
 * Surge 节点域名枚举器 v9(与模块 [Host] 合并方案配套)
 * 职责: 逐节点 [清缓存 -> identifier 探针 -> 读缓存] 归属出节点服务器域名,
 *       黑名单+信任过滤后在面板展示可信域名清单, 并把按当前参数生成的 [Host]
 *       指派行存入本地存储, 供日后机场更换节点域名时更新模块 [Host] 段对照。
 * 配置落地由模块机制本身完成: 本脚本所在的 .sgmodule 自带 [Host] 段,
 *       Surge 会把模块 [Host] 行自动合并进当前配置(本地 [Host] 为空也生效),
 *       脚本不再尝试写配置(实测 $httpAPI 未开放 profiles/section 写接口)。
 * 参数 doh1/doh2/boot1/boot2 与模块 [Host] 行共用同一组模块参数。
 */

const MAP_KEY = "dns_enum_map";
const RUNS_KEY = "dns_enum_domain_runs";
// 2026-11-25 两次全量枚举一致确认的机场后缀, 直接信任; 新后缀需满足信任规则才应用
const TRUSTED_SUFFIXES = ["chhbuv.cn", "inba996.com", "myinba55.com", "mcw.gay", "keyapisub.xyz"];
const BLOCK_KEY = "dns_enum_host_block";
const PROBE_URL = "http://cp.cloudflare.com/generate_204";
const PROBE_TIMEOUT_SEC = 3;
const TIME_BUDGET_MS = 200000;
const DEFAULT_DOH_SERVERS = [
    "https://alicdn-tbcdn-jdcdn-iycdn.mcw.gay/b13dc6533ab6db6cac6982acccec36e8/dns-query",
    "https://txcdn-tbcdn-bdcdn-ykcdn.mcw.gay/292f105ae785d1845a8799971ac3a14b/dns-query"
];

function resolveDohServers() {
    const fromArgs = [];
    if (typeof $argument !== "undefined" && $argument) {
        const text = String($argument);
        for (const key of ["doh1", "doh2", "doh3"]) {
            const match = text.match(new RegExp("(?:^|&)" + key + "=([^&]*)"));
            if (!match) continue;
            const value = match[1].trim().replace(/^["']|["']$/g, "");
            if (
                value &&
                !value.includes("{{{") &&
                !value.includes(",") &&
                /^(?:https?|tls|quic|h3):\/\//i.test(value)
            ) {
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
    ".wechat.com",
    ".alipay.com",
    ".alipayobjects.com",
    ".dianping.com",
    ".icloud-content.com",
    ".3gppnetwork.org",
    ".10086.cn",
    ".surge-activation.com",
    ".fastly-edge.com",
    ".metaaivm.com",
    ".cloudflare.com",
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

const MULTI_TLD = new Set(["com.cn", "net.cn", "org.cn", "gov.cn", "co.uk", "com.hk", "com.tw", "co.jp"]);

function regDomainOf(domain) {
    const parts = domain.split(".").filter(Boolean);
    if (parts.length <= 2) return domain;
    const last2 = parts.slice(-2).join(".");
    return parts.slice(-(MULTI_TLD.has(last2) ? 3 : 2)).join(".");
}

function extractHost(url) {
    const m = String(url).match(/^[a-z0-9+.-]+:\/\/(?:\[([^\]]+)\]|([^\/:?#]+))/i);
    return m ? (m[1] || m[2] || "").toLowerCase() : "";
}

function resolveBootstrapServers() {
    const found = [];
    if (typeof $argument !== "undefined" && $argument) {
        const text = String($argument);
        for (const key of ["boot1", "boot2"]) {
            const match = text.match(new RegExp("(?:^|&)" + key + "=([^&]*)"));
            if (match && match[1].trim()) found.push(match[1].trim());
        }
    }
    return found.length > 0 ? found : ["223.5.5.5", "119.29.29.29"];
}

const BOOTSTRAP_SERVERS = resolveBootstrapServers();

function buildHostLines(distinctDomains) {
    const serverList = DOH_SERVERS.join(",");
    const bootstrapList = BOOTSTRAP_SERVERS.join(",");
    const dohHostSuffixes = new Set();
    for (const server of DOH_SERVERS) {
        const host = extractHost(server);
        if (host && !isIpLike(host)) dohHostSuffixes.add(regDomainOf(host));
    }
    const hostLines = [];
    for (const suffix of Array.from(dohHostSuffixes).sort()) {
        hostLines.push(`*.${suffix} = server:${bootstrapList}`);
    }
    const cluster = new Map();
    for (const domain of distinctDomains) {
        const rd = regDomainOf(domain);
        cluster.set(rd, (cluster.get(rd) || 0) + 1);
    }
    const covered = new Set();
    const suffixes = Array.from(cluster.entries()).sort((a, b) => b[1] - a[1]);
    for (const [suffix, count] of suffixes) {
        if (count >= MIN_SUFFIX_COUNT && !dohHostSuffixes.has(suffix)) {
            hostLines.push(`*.${suffix} = server:${serverList}`);
            covered.add(suffix);
        }
    }
    for (const domain of distinctDomains) {
        const rd = regDomainOf(domain);
        if (dohHostSuffixes.has(rd)) continue;
        if (domain === rd) {
            hostLines.push(`${domain} = server:${serverList}`);
        } else if (!covered.has(rd)) {
            hostLines.push(`${domain} = server:${serverList}`);
        }
    }
    return hostLines;
}

function loadDomainRuns() {
    try {
        const raw = $persistentStore.read(RUNS_KEY);
        if (raw) {
            const parsed = JSON.parse(raw);
            if (parsed && typeof parsed === "object") return parsed;
        }
    } catch (_) {}
    return {};
}

function isTrustedDomain(domain, thisRunNodeCount, domainRuns) {
    const s2 = regDomainOf(domain);
    if (TRUSTED_SUFFIXES.includes(s2)) return true;
    if (thisRunNodeCount >= 3) return true;
    if ((domainRuns[domain] || 0) >= 2) return true;
    return false;
}

async function main() {
    const lines = [];
    try {
        let policiesRes = await httpApiAsync("GET", "/v1/policies", { include_external: "true" });
        if (!policiesRes || !Array.isArray(policiesRes["external-policies"])) {
            policiesRes = await httpApiAsync("GET", "/v1/policies?include_external=true");
        }
        const external = policiesRes && Array.isArray(policiesRes["external-policies"]) ? policiesRes["external-policies"] : [];

        const mapping = loadMap();
        const freshMap = {};
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
                if (name) freshMap[name] = [];
            } else if (name) {
                freshMap[name] = domains.slice().sort();
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
                if (!domain || isIpLike(domain) || isDenied(domain)) continue;
                if (!domainNodes.has(domain)) domainNodes.set(domain, []);
                domainNodes.get(domain).push(node);
            }
        }
        const thisRunNodes = new Map();
        for (const domains of Object.values(freshMap)) {
            for (const domain of domains) {
                thisRunNodes.set(domain, (thisRunNodes.get(domain) || 0) + 1);
            }
        }
        const domainRuns = loadDomainRuns();
        for (const domain of thisRunNodes.keys()) {
            domainRuns[domain] = (domainRuns[domain] || 0) + 1;
        }
        try {
            $persistentStore.write(JSON.stringify(domainRuns), RUNS_KEY);
        } catch (_) {}

        const allDomains = Array.from(domainNodes.keys()).sort();
        const distinctDomains = allDomains.filter((domain) =>
            isTrustedDomain(domain, thisRunNodes.get(domain) || 0, domainRuns)
        );
        const filteredNoise = allDomains.length - distinctDomains.length;
        const hostLines = buildHostLines(distinctDomains);
        try {
            $persistentStore.write(hostLines.join("\n"), BLOCK_KEY);
        } catch (_) {}


        lines.push(`外部节点: ${external.length} 个, 已逐个归属探针: ${probed} 个`);
        if (budgetHit) {
            lines.push("⏱ 本次时间预算内未探完(失效节点探针较慢), 已先用已探结果应用; 可再点一次补齐");
        }
        lines.push(`无域名节点(疑似纯IP): ${ipOnly} 个`);
        lines.push(`可信节点域名: ${distinctDomains.length} 个 (已过滤疑似噪声 ${filteredNoise} 个)`);
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
        lines.push(`已生成 [Host] 指派行: ${hostLines.length} 条 (已存本地, 与模块 [Host] 段对照用)`);
        lines.push("生效方式: 本模块 [Host] 段由 Surge 自动合并进配置");
        lines.push(`检查时间: ${formatTimeNow()}`);
        $done({
            title: `节点域名枚举v9 (${formatTimeNow()})`,
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
