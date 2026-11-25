/**
 * Surge 节点域名枚举器（通道B: DNS 缓存差分/累积）
 * 原理: 节点服务器域名由 Surge 本地解析, 必进 DNS 缓存; 走代理的目标域名在远端解析, 不进本地缓存。
 * 每次运行读取 /v1/dns 的 dnsCache, 把域名并入持久累积集, 按后缀聚类, 生成可直接使用的 [Host] 指派行。
 * 只读接口 + 本地持久存储, 不改配置, 不触发外部资源更新, 不拉取订阅。
 */

const STATE_KEY = "dns_enum_state";
const BLOCK_KEY = "dns_enum_host_block";
const DOH_SERVERS = [
    "https://radar.l9oauy.com:34683/dns-query/1dbbdec9-5627-41a2-bfb8-b195af6544c6",
    "https://8.163.85.149:44443/dns-query/1dbbdec9-5627-41a2-bfb8-b195af6544c6",
    "https://23.146.72.61:44443/dns-query/1dbbdec9-5627-41a2-bfb8-b195af6544c6"
];
const MIN_SUFFIX_COUNT = 2;
const MAX_PANEL_CLUSTERS = 10;

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
    "localhost"
]);

const DENY_SUFFIX = [
    ".apple.com",
    ".icloud.com",
    ".cdn-apple.com",
    ".mzstatic.com",
    ".googleapis.com",
    ".gstatic.com",
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

function loadState() {
    try {
        const raw = $persistentStore.read(STATE_KEY);
        if (raw) {
            const parsed = JSON.parse(raw);
            if (parsed && Array.isArray(parsed.domains)) return parsed;
        }
    } catch (_) {}
    return { domains: [], runs: 0 };
}

async function main() {
    const lines = [];
    try {
        const res = await httpApiAsync("GET", "/v1/dns");
        const cache = res && Array.isArray(res.dnsCache) ? res.dnsCache : [];
        const cacheDomains = [];
        for (const entry of cache) {
            if (entry && typeof entry.domain === "string") {
                const domain = entry.domain.trim().toLowerCase();
                if (domain && !isIpLike(domain) && !isDenied(domain)) {
                    cacheDomains.push(domain);
                }
            }
        }

        const state = loadState();
        const merged = new Set(state.domains);
        let newCount = 0;
        for (const domain of cacheDomains) {
            if (!merged.has(domain)) {
                merged.add(domain);
                newCount += 1;
            }
        }
        const allDomains = Array.from(merged).sort();
        const nextState = { domains: allDomains, runs: (state.runs || 0) + 1, updated: formatTimeNow() };
        try {
            $persistentStore.write(JSON.stringify(nextState), STATE_KEY);
        } catch (_) {}

        const cluster3 = new Map();
        const cluster2 = new Map();
        for (const domain of allDomains) {
            const s3 = suffixOf(domain, 3);
            const s2 = suffixOf(domain, 2);
            cluster3.set(s3, (cluster3.get(s3) || 0) + 1);
            cluster2.set(s2, (cluster2.get(s2) || 0) + 1);
        }
        const clusters = Array.from(cluster3.entries())
            .map(([suffix, count]) => ({ suffix, count, parent: suffixOf(suffix, 2), parentCount: cluster2.get(suffixOf(suffix, 2)) || 0 }))
            .sort((a, b) => b.count - a.count);

        const serverList = DOH_SERVERS.join(", ");
        const hostLines = [];
        for (const cluster of clusters) {
            if (cluster.count >= MIN_SUFFIX_COUNT) {
                hostLines.push(`*.${cluster.suffix} = server:${serverList}`);
            }
        }
        try {
            $persistentStore.write(hostLines.join("\n"), BLOCK_KEY);
        } catch (_) {}

        lines.push(`本次缓存域名: ${cacheDomains.length} 个, 新增: ${newCount} 个`);
        lines.push(`累积候选域名: ${allDomains.length} 个 (第 ${nextState.runs} 次运行)`);
        lines.push("后缀聚类 (三级 × 个数):");
        if (clusters.length === 0) {
            lines.push("暂无, 先刷新节点概览做一次全量测速再点本卡");
        } else {
            for (const cluster of clusters.slice(0, MAX_PANEL_CLUSTERS)) {
                lines.push(`${cluster.suffix} ×${cluster.count}`);
            }
            if (clusters.length > MAX_PANEL_CLUSTERS) {
                lines.push(`...其余 ${clusters.length - MAX_PANEL_CLUSTERS} 组见存储`);
            }
        }
        lines.push(`可生成 [Host] 指派行: ${hostLines.length} 条 (阈值 ≥${MIN_SUFFIX_COUNT})`);
        lines.push(`检查时间: ${formatTimeNow()}`);
        $done({
            title: `节点域名枚举 (${formatTimeNow()})`,
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
