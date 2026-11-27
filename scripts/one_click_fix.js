/**
 * Surge 一键调通与自愈按钮（兼容 policy-path 外部订阅节点）
 * 仅调用本地策略组测速与切换接口，不会触发任何订阅拉取或重载配置
 */

const RULESET_PROBE_URL = "https://raw.githubusercontent.com/minglala/proxy_rules/refs/heads/main/special_proxy_rules";
const PROBE_TIMEOUT_SEC = 5;
const HTTP_STATUS_OK_MIN = 200;
const HTTP_STATUS_OK_MAX = 400;
const EXPECTED_OUTBOUND_MODE = "rule";

const INFO_NODE_REGEX = /(负载均衡|剩余|流量|过期|重置|官网|套餐)/;
const BUILTIN_POLICIES = new Set(["DIRECT", "REJECT", "REJECT-TINYGIF"]);
const SOURCE_GROUPS = ["Quick", "Staryun"];
const REGION_GROUP_NAMES = ["🇭🇰香港", "🇸🇬新加坡", "🇯🇵日服", "🇺🇲美服"];

const LATENCY_UNTESTED = -2;
const LATENCY_FAILED = -1;
const LATENCY_ALIVE_UNKNOWN_MS = 0;
const SECONDS_THRESHOLD = 10;
const SECONDS_TO_MS = 1000;

// 各规则集对应的合规备选出口（Proxy 置顶确保下游依赖项能读取其最新状态）
const SERVICE_FALLBACK_RULES = [
    { group: "Proxy", label: "主代理", candidates: ["🇭🇰香港", "🇸🇬新加坡", "🇯🇵日服", "🇺🇲美服", "Quick", "Staryun"] },
    { group: "📟智能助理", label: "AI", candidates: ["🇺🇲美服", "🇯🇵日服", "🇸🇬新加坡"] },
    { group: "Google", label: "Google", candidates: ["🇸🇬新加坡", "🇯🇵日服", "🇺🇲美服", "🇭🇰香港"] },
    { group: "▶️Youtube", label: "YouTube", candidates: ["Proxy", "🇭🇰香港", "🇸🇬新加坡", "🇯🇵日服", "🇺🇲美服"] },
    { group: "Social Media", label: "社交", candidates: ["Proxy", "🇸🇬新加坡", "🇭🇰香港", "🇯🇵日服", "🇺🇲美服"] },
    { group: "Spotify", label: "Spotify", candidates: ["🇺🇲美服", "🇸🇬新加坡", "🇭🇰香港", "Proxy"] },
    { group: "☁️Others", label: "兜底", candidates: ["Proxy"] }
];

function httpApiAsync(method, path, body = {}) {
    return new Promise((resolve) => {
        $httpAPI(method, path, body, (res) => resolve(res || {}));
    });
}

function probeUrlAsync(url) {
    return new Promise((resolve) => {
        $httpClient.get({ url, timeout: PROBE_TIMEOUT_SEC }, (error, response) => {
            const ok = !error && response
                && response.status >= HTTP_STATUS_OK_MIN
                && response.status < HTTP_STATUS_OK_MAX;
            resolve(ok);
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

function mergeResults(benchRes, groupTestRes, nodes, latencyMap) {
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
    if (!groupTestRes || typeof groupTestRes !== "object") {
        return;
    }
    const byHash = new Map(nodes.map((n) => [n.lineHash, n.key]));
    for (const payload of Object.values(groupTestRes)) {
        for (const item of (Array.isArray(payload && payload.data) ? payload.data : [])) {
            const ms = parseBenchmarkEntry(item);
            if (ms !== LATENCY_UNTESTED && item.lineHash && byHash.has(item.lineHash)) {
                updateLatency(latencyMap, byHash.get(item.lineHash), ms);
            }
        }
    }
}

async function testGroupsAndBuildLatencyMap(groupsMap, groupNames, nodes) {
    const latencyMap = {};
    const testResponses = await Promise.all(
        groupNames.map(async (gName) => ({
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

    const [benchRes, groupTestRes] = await Promise.all([
        httpApiAsync("GET", "/v1/policies/benchmark_results"),
        httpApiAsync("GET", "/v1/policy_groups/test_results")
    ]);
    mergeResults(benchRes, groupTestRes, nodes, latencyMap);
    return latencyMap;
}

async function fetchSelectMap(groupNames) {
    const selectMap = {};
    await Promise.all(
        groupNames.map(async (name) => {
            const res = await httpApiAsync("GET", `/v1/policy_groups/select?group_name=${encodeURIComponent(name)}`);
            if (res && typeof res.policy === "string" && res.policy.length > 0) {
                selectMap[name] = res.policy;
            }
        })
    );
    return selectMap;
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

function getBestLatencyForPolicy(policyName, groupsMap, selectMap, latencyMap, visited = new Set()) {
    if (!policyName || visited.has(policyName) || BUILTIN_POLICIES.has(policyName)) {
        return LATENCY_FAILED;
    }
    visited.add(policyName);
    if (selectMap[policyName]) {
        return getBestLatencyForPolicy(selectMap[policyName], groupsMap, selectMap, latencyMap, visited);
    }
    const members = groupsMap[policyName];
    if (Array.isArray(members)) {
        let best = LATENCY_FAILED;
        for (const member of members) {
            if (!member || !member.name || INFO_NODE_REGEX.test(member.name)) {
                continue;
            }
            const ms = member.isGroup
                ? getBestLatencyForPolicy(member.name, groupsMap, selectMap, latencyMap, new Set(visited))
                : (latencyMap[getNodeKey(member)] ?? LATENCY_FAILED);
            if (isBetterLatency(ms, best)) {
                best = ms;
            }
        }
        return best;
    }
    return LATENCY_FAILED;
}

async function repairServiceGroups(groupsMap, selectMap, latencyMap) {
    const switched = [];
    const unreachable = [];

    for (const rule of SERVICE_FALLBACK_RULES) {
        if (!groupsMap[rule.group]) {
            continue;
        }
        const current = selectMap[rule.group] || "";
        const currentMs = getBestLatencyForPolicy(current, groupsMap, selectMap, latencyMap);
        if (currentMs >= LATENCY_ALIVE_UNKNOWN_MS && rule.candidates.includes(current)) {
            continue;
        }

        let chosen = "";
        let bestMs = LATENCY_FAILED;
        for (const candidate of rule.candidates) {
            const ms = getBestLatencyForPolicy(candidate, groupsMap, selectMap, latencyMap);
            if (isBetterLatency(ms, bestMs)) {
                bestMs = ms;
                chosen = candidate;
            }
        }

        if (chosen) {
            if (chosen !== current) {
                await httpApiAsync("POST", "/v1/policy_groups/select", { group_name: rule.group, policy: chosen });
                selectMap[rule.group] = chosen;
                const msTag = bestMs > 0 ? `${bestMs}ms` : "可用";
                switched.push(`${rule.label}->${chosen}(${msTag})`);
            }
        } else {
            unreachable.push(rule.label);
        }
    }
    return { switched, unreachable };
}

function formatTimeNow() {
    const now = new Date();
    const hh = String(now.getHours()).padStart(2, "0");
    const mm = String(now.getMinutes()).padStart(2, "0");
    const ss = String(now.getSeconds()).padStart(2, "0");
    return `${hh}:${mm}:${ss}`;
}

async function renderIdleState() {
    const outbound = await httpApiAsync("GET", "/v1/outbound");
    const mode = (outbound.mode || "unknown").toUpperCase();
    const isRuleMode = outbound.mode === EXPECTED_OUTBOUND_MODE;
    $done({
        title: "一键调通与自愈",
        content: `当前出站模式: ${mode}\n轻点此卡片执行：清缓存、断死链、重测地区组并自动切换失效分流出口`,
        icon: isRuleMode ? "wand.and.stars" : "exclamationmark.circle.fill",
        "icon-color": isRuleMode ? "#007AFF" : "#FF9500"
    });
}

async function runOneClickFix() {
    try {
        const actions = [];
        const outbound = await httpApiAsync("GET", "/v1/outbound");
        if (outbound.mode !== EXPECTED_OUTBOUND_MODE) {
            await httpApiAsync("POST", "/v1/outbound", { mode: EXPECTED_OUTBOUND_MODE });
            actions.push("出站已恢复 RULE");
        }

        await httpApiAsync("POST", "/v1/dns/flush");
        await httpApiAsync("POST", "/v1/requests/kill");
        actions.push("已清 DNS 与死链");

        const groupsMap = await httpApiAsync("GET", "/v1/policy_groups");
        const scanGroups = REGION_GROUP_NAMES.concat(SOURCE_GROUPS);
        const nodes = collectNodes(groupsMap, scanGroups);
        const latencyMap = await testGroupsAndBuildLatencyMap(groupsMap, scanGroups, nodes);

        const selectTargets = SERVICE_FALLBACK_RULES.map((r) => r.group).concat(SOURCE_GROUPS);
        const selectMap = await fetchSelectMap(selectTargets);
        const { switched, unreachable } = await repairServiceGroups(groupsMap, selectMap, latencyMap);
        const rulesetOk = await probeUrlAsync(RULESET_PROBE_URL);

        const summaryLines = [actions.join(" | ")];
        if (switched.length > 0) {
            summaryLines.push(`已切换: ${switched.join(", ")}`);
        } else if (unreachable.length === 0) {
            summaryLines.push("全部分流出口均畅通，无需切换");
        }
        if (unreachable.length > 0) {
            summaryLines.push(`无可用节点: ${unreachable.join(", ")}`);
        }
        summaryLines.push(rulesetOk ? "规则集源站: 连通正常" : "规则集源站: 访问超时，请检查主代理");

        summaryLines.push(`检查时间: ${formatTimeNow()}`);
        const allHealthy = unreachable.length === 0 && rulesetOk;
        $notification.post(
            allHealthy ? "Surge 一键调通完成" : "Surge 调通完成（存在异常项）",
            switched.length > 0 ? `已自动切换 ${switched.length} 个策略组` : "已完成缓存清理与链路校验",
            summaryLines.join("\n")
        );
        $done({
            title: allHealthy ? `一键调通 (${formatTimeNow()} · 全部畅通)` : `一键调通 (${formatTimeNow()} · 存在受阻)`,
            content: summaryLines.join("\n"),
            icon: allHealthy ? "checkmark.circle.fill" : "exclamationmark.triangle.fill",
            "icon-color": allHealthy ? "#34C759" : "#FF3B30"
        });
    } catch (err) {
        $done({
            title: `一键调通失败 (${formatTimeNow()})`,
            content: `执行异常: ${String(err)}`,
            icon: "xmark.circle.fill",
            "icon-color": "#FF3B30"
        });
    }
}

if (typeof $trigger !== "undefined" && $trigger === "button") {
    runOneClickFix();
} else {
    renderIdleState();
}
