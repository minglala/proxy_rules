/**
 * Surge 节点域名枚举器 v2（通道B 主动版）
 * 原理: 用 identifier 逐个经外部节点发一次探针请求, 迫使 Surge 本地解析每个节点的服务器域名,
 *       解析结果必进 DNS 缓存; 探针前后做缓存差分, 新增域名即节点域名候选。
 * 只读接口 + 本地持久存储, 不改配置, 不触发外部资源更新, 不拉取订阅。
 */

const STATE_KEY = "dns_enum_state";
const BLOCK_KEY = "dns_enum_host_block";
const PROBE_URL = "http://cp.cloudflare.com/generate_204";
const PROBE_BATCH = 12;
const PROBE_TIMEOUT_SEC = 6;
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
    "github.com",
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

async function readCacheDomains() {
    const res = await httpApiAsync("GET", "/v1/dns");
    const cache = res && Array.isArray(res.dnsCache) ? res.dnsCache : [];
    const domains = new Set();
    for (const entry of cache) {
        if (entry && typeof entry.domain === "string") {
            const domain = entry.domain.trim().toLowerCase();
            if (domain && !isIpLike(domain) && !isDenied(domain)) {
                domains.add(domain);
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

async function probeAll(identifiers) {
    let done = 0;
    for (let i = 0; i < identifiers.length; i += PROBE_BATCH) {
        const batch = identifiers.slice(i, i + PROBE_BATCH);
        await Promise.all(batch.map((id) => probeOnce(id)));
        done += batch.length;
    }
    return done;
}

async function main() {
    const lines = [];
    try {
        const before = await readCacheDomains();

        const policiesRes = await httpApiAsync("GET", "/v1/policies?include_external=true");
        const external = policiesRes && Array.isArray(policiesRes["external-policies"]) ? policiesRes["external-policies"] : [];
        const identifiers = external
            .map((item) => (item && typeof item.identifier === "string" ? item.identifier : ""))
            .filter(Boolean);

        let probed = 0;
        if (identifiers.length > 0) {
            probed = await probeAll(identifiers);
        }

        const after = await readCacheDomains();
        const fresh = [];
        for (const domain of after) {
            if (!before.has(domain)) fresh.push(domain);
        }

        const state = loadState();
        const merged = new Set(state.domains);
        for (const domain of after) merged.add(domain);
        for (const domain of fresh) merged.add(domain);
        const allDomains = Array.from(merged).sort();
        const nextState = { domains: allDomains, runs: (state.runs || 0) + 1, updated: formatTimeNow() };
        try {
            $persistentStore.write(JSON.stringify(nextState), STATE_KEY);
        } catch (_) {}

        const cluster2 = new Map();
        const cluster3 = new Map();
        for (const domain of allDomains) {
            const s2 = suffixOf(domain, 2);
            const s3 = suffixOf(domain, 3);
            cluster2.set(s2, (cluster2.get(s2) || 0) + 1);
            cluster3.set(s3, (cluster3.get(s3) || 0) + 1);
        }
        const clusters2 = Array.from(cluster2.entries())
            .map(([suffix, count]) => ({ suffix, count }))
            .sort((a, b) => b.count - a.count);
        const clusters3 = Array.from(cluster3.entries())
            .map(([suffix, count]) => ({ suffix, count }))
            .sort((a, b) => b.count - a.count);

        const serverList = DOH_SERVERS.join(", ");
        const hostLines = [];
        for (const cluster of clusters2) {
            if (cluster.count >= MIN_SUFFIX_COUNT) {
                hostLines.push(`*.${cluster.suffix} = server:${serverList}`);
            }
        }
        try {
            $persistentStore.write(hostLines.join("\n"), BLOCK_KEY);
        } catch (_) {}

        lines.push(`外部节点: ${external.length} 个, 已逐个探针: ${probed} 个`);
        lines.push(`探针新增域名: ${fresh.length} 个`);
        lines.push(`累积候选域名: ${allDomains.length} 个 (第 ${nextState.runs} 次运行)`);
        lines.push("二级后缀聚类 (域名 × 个数):");
        if (clusters2.length === 0) {
            lines.push("暂无候选");
        } else {
            for (const cluster of clusters2.slice(0, MAX_PANEL_CLUSTERS)) {
                lines.push(`${cluster.suffix} ×${cluster.count}`);
            }
            if (clusters2.length > MAX_PANEL_CLUSTERS) {
                lines.push(`...其余 ${clusters2.length - MAX_PANEL_CLUSTERS} 组见存储`);
            }
        }
        const top3 = clusters3.slice(0, 3).map((c) => `${c.suffix} ×${c.count}`).join(", ");
        if (top3) lines.push(`三级示例: ${top3}`);
        lines.push(`可生成 [Host] 指派行: ${hostLines.length} 条 (二级后缀 ≥${MIN_SUFFIX_COUNT})`);
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
