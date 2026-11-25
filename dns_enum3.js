/**
 * Surge 节点域名枚举器 v3（通道B 归属版）
 * 原理: 对每个外部节点循环 [清空DNS缓存 -> 用 identifier 经该节点发一次探针 -> 读缓存],
 *       探针后缓存里新出现的域名即该节点的服务器域名, 可精确归属到节点;
 *       若探针后无新域名, 该节点服务器大概率是纯 IP。
 * 只读接口 + 本地持久存储, 不改配置, 不触发外部资源更新, 不拉取订阅。
 * 注意: 过程会反复清空 DNS 缓存(仅缓存, 会自然重建), 全程约 1-3 分钟。
 */

const MAP_KEY = "dns_enum_map";
const BLOCK_KEY = "dns_enum_host_block";
const PROBE_URL = "http://cp.cloudflare.com/generate_204";
const PROBE_TIMEOUT_SEC = 4;
const DOH_SERVERS = [
    "https://radar.l9oauy.com:34683/dns-query/1dbbdec9-5627-41a2-bfb8-b195af6544c6",
    "https://8.163.85.149:44443/dns-query/1dbbdec9-5627-41a2-bfb8-b195af6544c6",
    "https://23.146.72.61:44443/dns-query/1dbbdec9-5627-41a2-bfb8-b195af6544c6"
];
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
        $httpClient.get({ url: PROBE_URL, timeout: PROBE_TIMEOUT_SEC, policy: identifier }, () => resolve(true));
    });
}

async function main() {
    const lines = [];
    try {
        const policiesRes = await httpApiAsync("GET", "/v1/policies?include_external=true");
        const external = policiesRes && Array.isArray(policiesRes["external-policies"]) ? policiesRes["external-policies"] : [];

        const mapping = loadMap();
        let ipOnly = 0;
        let probed = 0;
        for (const item of external) {
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

        const cluster2 = new Map();
        for (const domain of distinctDomains) {
            const s2 = suffixOf(domain, 2);
            cluster2.set(s2, (cluster2.get(s2) || 0) + 1);
        }
        const clusters2 = Array.from(cluster2.entries())
            .map(([suffix, count]) => ({ suffix, count }))
            .sort((a, b) => b.count - a.count);

        const serverList = DOH_SERVERS.join(", ");
        const hostLines = [];
        for (const cluster of clusters2) {
            if (cluster.count >= MIN_SUFFIX_COUNT) {
                hostLines.push(`*.${cluster.suffix} = server:${serverList}`);
            }
        }
        for (const domain of distinctDomains) {
            if ((cluster2.get(suffixOf(domain, 2)) || 0) < MIN_SUFFIX_COUNT) {
                hostLines.push(`${domain} = server:${serverList}`);
            }
        }
        try {
            $persistentStore.write(hostLines.join("\n"), BLOCK_KEY);
        } catch (_) {}

        lines.push(`外部节点: ${external.length} 个, 已逐个归属探针: ${probed} 个`);
        lines.push(`无域名节点(疑似纯IP): ${ipOnly} 个`);
        lines.push(`不同节点域名: ${distinctDomains.length} 个`);
        lines.push("节点域名清单 (域名 ← 节点数):");
        if (distinctDomains.length === 0) {
            lines.push("暂无, 探针可能被节点协议阻挡, 见存储映射");
        } else {
            for (const domain of distinctDomains.slice(0, MAX_PANEL_DOMAINS)) {
                lines.push(`${domain} ← ${domainNodes.get(domain).length}`);
            }
            if (distinctDomains.length > MAX_PANEL_DOMAINS) {
                lines.push(`...其余 ${distinctDomains.length - MAX_PANEL_DOMAINS} 个见存储`);
            }
        }
        lines.push(`可生成 [Host] 指派行: ${hostLines.length} 条`);
        lines.push(`检查时间: ${formatTimeNow()}`);
        $done({
            title: `节点域名枚举v3 (${formatTimeNow()})`,
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
