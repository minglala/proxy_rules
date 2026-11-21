/**
 * Surge 定时静默巡检与无感自愈脚本
 * 触发类型: cron (每 30 分钟执行一次)
 * 正常时零打扰；仅在主代理或 AI 出口受阻时自动切换合规出口并推送告警
 */

const EXPECTED_OUTBOUND_MODE = "rule";
const POLICY_PROXY = "Proxy";
const POLICY_AI = "📟智能助理";

const PROXY_PROBE_URL = "http://cp.cloudflare.com/generate_204";
const CHATGPT_TRACE_URL = "https://chatgpt.com/cdn-cgi/trace";
const OPENAI_API_URL = "https://api.openai.com/v1/models";

const PROBE_TIMEOUT_SEC = 6;
// 模块可编辑参数（通过 argument=cooldown_hours=<小时>;probe_timeout=<秒> 传入，未传时用默认值）
let probeTimeoutSec = PROBE_TIMEOUT_SEC;
let alertCooldownMs = 2 * 60 * 60 * 1000;
(function parseModuleArguments() {
    try {
        const raw = (typeof $argument !== "undefined") ? $argument : "";
        const pairs = {};
        if (typeof raw === "string" && raw) {
            for (const part of raw.split(";")) {
                const idx = part.indexOf("=");
                if (idx > 0) {
                    pairs[part.substring(0, idx).trim()] = part.substring(idx + 1).trim();
                }
            }
        } else if (raw && typeof raw === "object") {
            Object.assign(pairs, raw);
        }
        const cooldownHours = Number(pairs.cooldown_hours);
        if (Number.isFinite(cooldownHours) && cooldownHours > 0) {
            alertCooldownMs = cooldownHours * 60 * 60 * 1000;
        }
        const probeTimeout = Number(pairs.probe_timeout);
        if (Number.isFinite(probeTimeout) && probeTimeout > 0) {
            probeTimeoutSec = probeTimeout;
        }
    } catch (_) {
        // 参数解析失败时保持默认值
    }
})();
const HTTP_OK = 200;
const HTTP_NO_CONTENT = 204;
const HTTP_UNAUTHORIZED = 401;
const HTTP_FORBIDDEN = 403;

const UNSUPPORTED_AI_REGIONS = new Set(["CN", "HK", "MO", "RU", "BY", "IR", "KP", "CU", "SY", "AF", "VE"]);
const INFO_NODE_REGEX = /(负载均衡|剩余|流量|过期|重置|官网|套餐)/;
const BUILTIN_POLICIES = new Set(["DIRECT", "REJECT", "REJECT-TINYGIF"]);

const REGION_GROUPS = ["🇭🇰香港", "🇸🇬新加坡", "🇯🇵日服", "🇺🇲美服"];
const PROXY_CANDIDATES = ["🇭🇰香港", "🇸🇬新加坡", "🇯🇵日服", "🇺🇲美服"];
const AI_CANDIDATES = ["🇺🇲美服", "🇯🇵日服", "🇸🇬新加坡"];

const LATENCY_UNTESTED = -2;
const LATENCY_FAILED = -1;
const LATENCY_ALIVE_UNKNOWN_MS = 0;
const SECONDS_THRESHOLD = 10;
const SECONDS_TO_MS = 1000;

const STORAGE_ALERT_TS_KEY = "surge_silent_watchdog_last_alert_ts";
const STORAGE_ALERT_SIG_KEY = "surge_silent_watchdog_last_alert_sig";

function httpApiAsync(method, path, body = {}) {
    return new Promise((resolve) => {
        $httpAPI(method, path, body, (res) => resolve(res || {}));
    });
}

function httpGetAsync(url, policy) {
    return new Promise((resolve) => {
        const opts = { url, timeout: probeTimeoutSec };
        if (policy) {
            opts.policy = policy;
        }
        $httpClient.get(opts, (error, response, data) => {
            resolve({
                error: error || null,
                status: response ? response.status : 0,
                body: typeof data === "string" ? data : ""
            });
        });
    });
}

function normalizeMs(rawValue, allowSeconds) {
    if (typeof rawValue !== "number" || Number.isNaN(rawValue) || rawValue <= 0) {
        return LATENCY_FAILED;
    }
    if (allowSeconds && rawValue < SECONDS_THRESHOLD) {
        return Math.round(rawValue * SECONDS_TO_MS);
    }
    return Math.round(rawValue);
}

function parseBenchmarkEntry(entry) {
    if (entry === null || entry === undefined) {
        return LATENCY_UNTESTED;
    }
    if (typeof entry === "number") {
        return normalizeMs(entry, true);
    }
    if (typeof entry !== "object") {
        return LATENCY_UNTESTED;
    }
    if (entry.alive === false || entry.lastTestErrorMessage || entry.error) {
        return LATENCY_FAILED;
    }
    for (const key of ["lastTestScoreInMS", "scoreInMS", "delay", "latency"]) {
        if (typeof entry[key] === "number") {
            return normalizeMs(entry[key], false);
        }
    }
    for (const key of ["rtt", "time", "score"]) {
        if (typeof entry[key] === "number") {
            return normalizeMs(entry[key], true);
        }
    }
    return LATENCY_UNTESTED;
}

function getNodeKey(member) {
    return (member && member.lineHash) ? member.lineHash : (member && member.name ? member.name : "");
}

function collectNodes(groupsMap, groupNames) {
    const nodeMap = new Map();
    for (const gName of groupNames) {
        for (const member of (groupsMap[gName] || [])) {
            const name = member && member.name;
            if (!name || member.isGroup || BUILTIN_POLICIES.has(name) || INFO_NODE_REGEX.test(name)) {
                continue;
            }
            const key = getNodeKey(member);
            if (key && !nodeMap.has(key)) {
                nodeMap.set(key, { key, name, lineHash: member.lineHash || "" });
            }
        }
    }
    return Array.from(nodeMap.values());
}

function updateLatency(latencyMap, key, value) {
    const prev = latencyMap[key];
    if (value > 0) {
        latencyMap[key] = value;
    } else if (value === LATENCY_ALIVE_UNKNOWN_MS && (prev === undefined || prev < 0)) {
        latencyMap[key] = value;
    } else if (value === LATENCY_FAILED && (prev === undefined || prev === LATENCY_UNTESTED)) {
        latencyMap[key] = value;
    }
}

function isBetterLatency(candidateMs, bestMs) {
    if (candidateMs < LATENCY_ALIVE_UNKNOWN_MS) {
        return false;
    }
    if (bestMs < LATENCY_ALIVE_UNKNOWN_MS) {
        return true;
    }
    if (candidateMs > 0 && bestMs === LATENCY_ALIVE_UNKNOWN_MS) {
        return true;
    }
    return candidateMs > 0 && bestMs > 0 && candidateMs < bestMs;
}

async function probeProxyHealth() {
    const res = await httpGetAsync(PROXY_PROBE_URL, POLICY_PROXY);
    const ok = !res.error && (res.status === HTTP_NO_CONTENT || res.status === HTTP_OK);
    return { ok, reason: ok ? "" : "主代理连接超时" };
}

async function probeAiHealth() {
    const [traceRes, apiRes] = await Promise.all([
        httpGetAsync(CHATGPT_TRACE_URL, POLICY_AI),
        httpGetAsync(OPENAI_API_URL, POLICY_AI)
    ]);
    const locMatch = traceRes.body.match(/^loc=([A-Z]{2})/m);
    const loc = locMatch ? locMatch[1] : "";

    if (loc && UNSUPPORTED_AI_REGIONS.has(loc)) {
        return { ok: false, reason: `AI 出口地区受限(${loc})` };
    }
    if (apiRes.status === HTTP_UNAUTHORIZED) {
        return { ok: true, reason: "" };
    }
    if (apiRes.status === HTTP_FORBIDDEN) {
        return { ok: false, reason: `AI 出口触发风控(${loc || "403"})` };
    }
    if (traceRes.status === HTTP_OK && loc) {
        return { ok: true, reason: "" };
    }
    return { ok: false, reason: "AI 出口访问超时" };
}

async function measureRegionLatencies(groupsMap) {
    const latencyMap = {};
    const nodes = collectNodes(groupsMap, REGION_GROUPS);
    const testResponses = await Promise.all(
        REGION_GROUPS.map(async (gName) => ({
            gName,
            res: await httpApiAsync("POST", "/v1/policy_groups/test", { group_name: gName })
        }))
    );

    for (const { gName, res } of testResponses) {
        const availableSet = new Set(Array.isArray(res.available) ? res.available : []);
        for (const member of (groupsMap[gName] || [])) {
            const name = member && member.name;
            if (!name || member.isGroup || BUILTIN_POLICIES.has(name) || INFO_NODE_REGEX.test(name)) {
                continue;
            }
            const key = getNodeKey(member);
            if (availableSet.has(name)) {
                updateLatency(latencyMap, key, LATENCY_ALIVE_UNKNOWN_MS);
            } else if (Array.isArray(res.available)) {
                updateLatency(latencyMap, key, LATENCY_FAILED);
            }
        }
    }

    const benchRes = await httpApiAsync("GET", "/v1/policies/benchmark_results");
    const benchDict = (benchRes && typeof benchRes.results === "object") ? benchRes.results : benchRes;
    if (benchDict && typeof benchDict === "object") {
        for (const node of nodes) {
            const entry = (node.lineHash && benchDict[node.lineHash] !== undefined)
                ? benchDict[node.lineHash]
                : benchDict[node.name];
            const parsed = parseBenchmarkEntry(entry);
            if (parsed !== LATENCY_UNTESTED) {
                updateLatency(latencyMap, node.key, parsed);
            }
        }
    }

    const regionBest = {};
    for (const gName of REGION_GROUPS) {
        let best = LATENCY_FAILED;
        for (const member of (groupsMap[gName] || [])) {
            if (!member || member.isGroup || INFO_NODE_REGEX.test(member.name || "")) {
                continue;
            }
            const ms = latencyMap[getNodeKey(member)] ?? LATENCY_FAILED;
            if (isBetterLatency(ms, best)) {
                best = ms;
            }
        }
        regionBest[gName] = best;
    }
    return regionBest;
}

async function switchToBestAlternative(groupName, candidates, regionBest) {
    const selRes = await httpApiAsync("GET", `/v1/policy_groups/select?group_name=${encodeURIComponent(groupName)}`);
    const current = selRes.policy || "";

    let chosen = "";
    let bestMs = LATENCY_FAILED;
    for (const candidate of candidates) {
        if (candidate === current) {
            continue;
        }
        const ms = regionBest[candidate] ?? LATENCY_FAILED;
        if (isBetterLatency(ms, bestMs)) {
            bestMs = ms;
            chosen = candidate;
        }
    }

    if (!chosen) {
        return { switched: false, text: `${groupName} 无可用备选地区` };
    }
    await httpApiAsync("POST", "/v1/policy_groups/select", { group_name: groupName, policy: chosen });
    const msTag = bestMs > 0 ? `${bestMs}ms` : "可用";
    return { switched: true, text: `${groupName} 已切至 ${chosen}(${msTag})` };
}

function shouldSendNotification(signature) {
    const now = Date.now();
    const lastTs = Number($persistentStore.read(STORAGE_ALERT_TS_KEY) || "0");
    const lastSig = $persistentStore.read(STORAGE_ALERT_SIG_KEY) || "";
    if (signature === lastSig && (now - lastTs) < alertCooldownMs) {
        return false;
    }
    $persistentStore.write(String(now), STORAGE_ALERT_TS_KEY);
    $persistentStore.write(signature, STORAGE_ALERT_SIG_KEY);
    return true;
}

function clearAlertCooldown() {
    if ($persistentStore.read(STORAGE_ALERT_SIG_KEY)) {
        $persistentStore.write("", STORAGE_ALERT_SIG_KEY);
        $persistentStore.write("0", STORAGE_ALERT_TS_KEY);
    }
}

async function main() {
    try {
        const outbound = await httpApiAsync("GET", "/v1/outbound");
        if (outbound.mode !== EXPECTED_OUTBOUND_MODE) {
            $done();
            return;
        }

        const [proxyStatus, aiStatus] = await Promise.all([
            probeProxyHealth(),
            probeAiHealth()
        ]);

        if (proxyStatus.ok && aiStatus.ok) {
            clearAlertCooldown();
            $done();
            return;
        }

        const issues = [];
        const actions = [];
        if (!proxyStatus.ok) {
            issues.push(proxyStatus.reason);
        }
        if (!aiStatus.ok) {
            issues.push(aiStatus.reason);
        }

        await httpApiAsync("POST", "/v1/dns/flush");
        const groupsMap = await httpApiAsync("GET", "/v1/policy_groups");
        const regionBest = await measureRegionLatencies(groupsMap);

        if (!proxyStatus.ok && groupsMap[POLICY_PROXY]) {
            const res = await switchToBestAlternative(POLICY_PROXY, PROXY_CANDIDATES, regionBest);
            actions.push(res.text);
        }
        if (!aiStatus.ok && groupsMap[POLICY_AI]) {
            const res = await switchToBestAlternative(POLICY_AI, AI_CANDIDATES, regionBest);
            actions.push(res.text);
        }

        const signature = `${issues.join("|")}::${actions.join("|")}`;
        if (shouldSendNotification(signature)) {
            $notification.post(
                "Surge 静默巡检发现异常",
                issues.join("；"),
                actions.length > 0 ? actions.join("\n") : "请打开 Surge 检查节点或网络状态"
            );
        }
    } catch (err) {
        console.log(`Silent watchdog error: ${String(err)}`);
    } finally {
        $done();
    }
}

main();
