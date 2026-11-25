/**
 * Surge 节点 DNS 枚举探针（只读）
 * 目的: 验证自动枚举节点服务器域名的三条通道是否可用
 *  1. GET /v1/policies?include_external=true 是否返回 external-policies
 *  2. GET /v1/policies/detail 对外部节点返回哪些字段（只报字段名与类型, 不报值, 不碰密码类字段）
 *  3. GET /v1/dns 的缓存结构（只报条数与首条字段名）
 * 本脚本不修改任何配置, 不触发外部资源更新, 不拉取订阅。
 */

const STORE_KEY = "dns_probe_last";
const SERVER_KEY_PATTERN = /server|host|address|domain|ip/i;
const MAX_KEYS_LISTED = 40;

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

function typeOf(value) {
    if (Array.isArray(value)) return `array(${value.length})`;
    if (value === null) return "null";
    return typeof value;
}

function describeKeys(obj, depth) {
    if (!obj || typeof obj !== "object" || Array.isArray(obj)) return [];
    const out = [];
    for (const key of Object.keys(obj)) {
        out.push(`${key}:${typeOf(obj[key])}`);
        if (depth > 0 && obj[key] && typeof obj[key] === "object" && !Array.isArray(obj[key])) {
            for (const sub of Object.keys(obj[key]).slice(0, MAX_KEYS_LISTED)) {
                out.push(`${key}.${sub}:${typeOf(obj[key][sub])}`);
            }
        }
    }
    return out;
}

function findServerKeys(obj, prefix, hits) {
    if (!obj || typeof obj !== "object") return hits;
    for (const key of Object.keys(obj)) {
        const path = prefix ? `${prefix}.${key}` : key;
        if (SERVER_KEY_PATTERN.test(key) && typeof obj[key] === "string") {
            hits.push(path);
        }
        if (obj[key] && typeof obj[key] === "object" && !Array.isArray(obj[key]) && !prefix) {
            findServerKeys(obj[key], path, hits);
        }
    }
    return hits;
}

async function probePolicies(lines, report) {
    const res = await httpApiAsync("GET", "/v1/policies?include_external=true");
    const proxies = Array.isArray(res.proxies) ? res.proxies : [];
    const groups = Array.isArray(res["policy-groups"]) ? res["policy-groups"] : [];
    const external = Array.isArray(res["external-policies"]) ? res["external-policies"] : null;
    report.proxiesCount = proxies.length;
    report.groupsCount = groups.length;
    report.externalCount = external ? external.length : -1;
    lines.push(`本地策略: ${proxies.length} 个, 策略组: ${groups.length} 个`);
    if (external === null) {
        lines.push("外部节点: 接口未返回 external-policies 字段");
        lines.push("(可能 Surge 版本低于 iOS 6.0, 通道A需改走缓存差分)");
        return null;
    }
    lines.push(`外部节点: ${external.length} 个 (通道A 列表可用)`);
    if (external.length > 0) {
        const first = external[0] || {};
        report.externalSampleKeys = describeKeys(first, 0);
        lines.push(`外部条目字段: ${report.externalSampleKeys.join(", ") || "无"}`);
        return first;
    }
    return null;
}

async function probeDetail(lines, report, externalFirst, policiesRes) {
    let targetName = "";
    let targetId = "";
    if (externalFirst) {
        targetName = typeof externalFirst.name === "string" ? externalFirst.name : "";
        targetId = typeof externalFirst.identifier === "string" ? externalFirst.identifier : "";
    }
    if (!targetName && policiesRes && Array.isArray(policiesRes.proxies) && policiesRes.proxies.length > 0) {
        targetName = policiesRes.proxies[0];
    }
    if (!targetName && !targetId) {
        lines.push("详情探测: 没有可用的节点样本, 跳过");
        return;
    }
    const attempts = [];
    if (targetName) attempts.push({ label: "按名称", value: targetName });
    if (targetId && targetId !== targetName) attempts.push({ label: "按identifier", value: targetId });
    for (const attempt of attempts) {
        const encoded = encodeURIComponent(attempt.value);
        const detail = await httpApiAsync("GET", `/v1/policies/detail?policy_name=${encoded}`);
        if (detail && typeof detail.error === "string") {
            lines.push(`详情探测(${attempt.label}): 接口报错 ${detail.error.slice(0, 60)}`);
            continue;
        }
        const keys = describeKeys(detail, 1);
        if (keys.length === 0) {
            lines.push(`详情探测(${attempt.label}): 返回为空或无字段`);
            continue;
        }
        const serverKeys = findServerKeys(detail, "", []);
        report.detailAttempt = attempt.label;
        report.detailKeys = keys;
        report.detailServerKeys = serverKeys;
        lines.push(`详情探测(${attempt.label}): 共 ${keys.length} 个字段`);
        lines.push(`字段: ${keys.slice(0, MAX_KEYS_LISTED).join(", ")}`);
        lines.push(serverKeys.length > 0
            ? `含服务器类字段: ${serverKeys.join(", ")} → 通道A 成立`
            : "未发现服务器类字段 → 通道A 不成立, 走通道B");
        return;
    }
}

async function probeDnsCache(lines, report) {
    const res = await httpApiAsync("GET", "/v1/dns");
    if (Array.isArray(res)) {
        report.dnsType = "array";
        report.dnsCount = res.length;
        lines.push(`DNS缓存: 数组, ${res.length} 条`);
        if (res.length > 0) {
            const keys = describeKeys(res[0], 0);
            report.dnsSampleKeys = keys;
            lines.push(`首条字段: ${keys.join(", ") || "非对象"}`);
        }
        return;
    }
    if (res && typeof res === "object") {
        const topKeys = Object.keys(res);
        report.dnsType = "object";
        report.dnsTopKeys = topKeys.slice(0, MAX_KEYS_LISTED);
        lines.push(`DNS缓存: 对象, 顶层字段 ${topKeys.length} 个`);
        lines.push(`顶层字段: ${report.dnsTopKeys.join(", ") || "无"}`);
        for (const key of topKeys) {
            const value = res[key];
            if (Array.isArray(value)) {
                lines.push(`字段 ${key}: 数组 ${value.length} 条`);
                if (value.length > 0) {
                    const keys = describeKeys(value[0], 0);
                    lines.push(`字段 ${key} 首条字段: ${keys.join(", ") || "非对象"}`);
                }
            } else if (value && typeof value === "object") {
                const subKeys = Object.keys(value);
                lines.push(`字段 ${key}: 对象 ${subKeys.length} 个键`);
                if (subKeys.length > 0) {
                    const firstVal = value[subKeys[0]];
                    if (firstVal && typeof firstVal === "object" && !Array.isArray(firstVal)) {
                        const keys = describeKeys(firstVal, 0);
                        lines.push(`字段 ${key} 首值字段: ${keys.join(", ") || "非对象"}`);
                    } else {
                        lines.push(`字段 ${key} 首值类型: ${typeOf(firstVal)}`);
                    }
                }
            } else {
                lines.push(`字段 ${key}: ${typeOf(value)}`);
            }
        }
        if (res.dnsCache !== undefined) {
            report.dnsCacheType = typeOf(res.dnsCache);
            lines.push("已定位 dnsCache 字段 → 通道B 按此结构落地");
        }
        return;
    }
    lines.push("DNS缓存: 返回为空, 通道B 待确认");
}

async function main() {
    const lines = [];
    const report = { time: formatTimeNow() };
    try {
        const externalFirst = await probePolicies(lines, report);
        const policiesRes = await httpApiAsync("GET", "/v1/policies?include_external=true");
        await probeDetail(lines, report, externalFirst, policiesRes);
    } catch (err) {
        lines.push(`策略探测异常: ${String(err)}`);
    }
    try {
        await probeDnsCache(lines, report);
    } catch (err) {
        lines.push(`缓存探测异常: ${String(err)}`);
    }
    lines.push(`检查时间: ${formatTimeNow()}`);
    try {
        $persistentStore.write(JSON.stringify(report), STORE_KEY);
    } catch (_) {}
    $done({
        title: `节点DNS探针 (${formatTimeNow()})`,
        content: lines.join("\n"),
        icon: "magnifyingglass",
        "icon-color": "#007AFF"
    });
}

main();
