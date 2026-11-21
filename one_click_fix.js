/**
 * Surge 一键调通自愈按钮
 * 点击面板触发：恢复规则模式、清理缓存与死链、重测地区组、自动切换失效分流出口、校验规则集连通性
 */

const TEST_URL = "http://cp.cloudflare.com/generate_204";
const RULESET_PROBE_URL = "https://raw.githubusercontent.com/minglala/proxy_rules/refs/heads/main/special_proxy_rules";
const PROBE_TIMEOUT_SEC = 5;
const EXPECTED_OUTBOUND_MODE = "rule";
const INFO_NODE_REGEX = /(负载均衡|剩余|流量|过期|重置|官网|套餐)/;
const BUILTIN_POLICIES = new Set(["DIRECT", "REJECT", "REJECT-TINYGIF"]);
const INVALID_LATENCY = -1;
const SECONDS_THRESHOLD = 10;
const SECONDS_TO_MS = 1000;

const REGION_GROUP_NAMES = ["🇭🇰香港", "🇸🇬新加坡", "🇯🇵日服", "🇺🇲美服"];

// 各规则集对应的合规备选出口（AI 严格排除香港节点防风控，Google 优先新加坡防验证码）
const SERVICE_FALLBACK_RULES = [
    { group: "Proxy", label: "主代理", candidates: ["🇭🇰香港", "🇸🇬新加坡", "🇯🇵日服", "🇺🇲美服", "Quick", "Staryun"] },
    { group: "📟智能助理", label: "AI", candidates: ["🇺🇲美服", "🇯🇵日服", "🇸🇬新加坡"] },
    { group: "Google", label: "Google", candidates: ["🇸🇬新加坡", "🇯🇵日服", "🇺🇲美服", "🇭🇰香港"] },
    { group: "▶️Youtube", label: "YouTube", candidates: ["🇭🇰香港", "🇸🇬新加坡", "🇯🇵日服", "🇺🇲美服"] },
    { group: "Social Media", label: "社交", candidates: ["🇸🇬新加坡", "🇭🇰香港", "🇯🇵日服", "🇺🇲美服"] },
    { group: "Spotify", label: "Spotify", candidates: ["🇺🇲美服", "🇸🇬新加坡", "🇭🇰香港"] },
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
            const ok = !error && response && response.status >= 200 && response.status < 400;
            resolve(ok);
        });
    });
}

function parseLatencyMs(entry) {
    if (entry === null || entry === undefined) {
        return INVALID_LATENCY;
    }
    if (typeof entry === "number") {
        if (entry <= 0) {
            return INVALID_LATENCY;
        }
        return entry < SECONDS_THRESHOLD ? Math.round(entry * SECONDS_TO_MS) : Math.round(entry);
    }
    if (typeof entry === "object") {
        if (entry.alive === false || entry.error) {
            return INVALID_LATENCY;
        }
        const raw = entry.rtt !== undefined ? entry.rtt : entry.delay;
        if (typeof raw === "number" && raw > 0) {
            return raw < SECONDS_THRESHOLD ? Math.round(raw * SECONDS_TO_MS) : Math.round(raw);
        }
    }
    return INVALID_LATENCY;
}

function collectNodes(groupsMap, groupNames) {
    const nodeSet = new Set();
    for (const gName of groupNames) {
        const members = groupsMap[gName] || [];
        for (const member of members) {
            const name = member && member.name;
            if (!name || member.isGroup || BUILTIN_POLICIES.has(name) || INFO_NODE_REGEX.test(name)) {
                continue;
            }
            nodeSet.add(name);
        }
    }
    return Array.from(nodeSet);
}

function getBestLatencyForPolicy(policyName, groupsMap, latencyMap, visited = new Set()) {
    if (!policyName || visited.has(policyName) || BUILTIN_POLICIES.has(policyName)) {
        return INVALID_LATENCY;
    }
    visited.add(policyName);
    const members = groupsMap[policyName];
    if (Array.isArray(members)) {
        let best = Infinity;
        for (const member of members) {
            if (!member || INFO_NODE_REGEX.test(member.name)) {
                continue;
            }
            const ms = getBestLatencyForPolicy(member.name, groupsMap, latencyMap, new Set(visited));
            if (ms > 0 && ms < best) {
                best = ms;
            }
        }
        return best < Infinity ? best : INVALID_LATENCY;
    }
    return latencyMap[policyName] || INVALID_LATENCY;
}

async function renderIdleState() {
    const outbound = await httpApiAsync("GET", "/v1/outbound");
    const mode = (outbound.mode || "unknown").toUpperCase();
    const isRuleMode = outbound.mode === EXPECTED_OUTBOUND_MODE;
    $done({
        title: "一键调通与自愈",
        content: `当前出站模式: ${mode}\n轻点此卡片执行：清缓存、断死链、重测地区组并自动切换失效规则集出口`,
        icon: isRuleMode ? "wand.and.stars" : "exclamationmark.circle.fill",
        "icon-color": isRuleMode ? "#007AFF" : "#FF9500"
    });
}

async function repairServiceGroups(groupsMap, latencyMap) {
    const switched = [];
    const unreachable = [];

    for (const rule of SERVICE_FALLBACK_RULES) {
        if (!groupsMap[rule.group]) {
            continue;
        }
        const encoded = encodeURIComponent(rule.group);
        const selRes = await httpApiAsync("GET", `/v1/policy_groups/select?group_name=${encoded}`);
        const current = selRes.policy || "";
        const currentBestMs = getBestLatencyForPolicy(current, groupsMap, latencyMap);

        // 若当前策略已连通且位于合规候选内，则保持现状不频繁抖动
        if (currentBestMs > 0 && rule.candidates.includes(current)) {
            continue;
        }

        // 从合规候选列表中挑选当前延迟最低的可用出口
        let chosen = "";
        let bestMs = Infinity;
        for (const candidate of rule.candidates) {
            const ms = getBestLatencyForPolicy(candidate, groupsMap, latencyMap);
            if (ms > 0 && ms < bestMs) {
                bestMs = ms;
                chosen = candidate;
            }
        }

        if (chosen) {
            if (chosen !== current) {
                await httpApiAsync("POST", "/v1/policy_groups/select", {
                    group_name: rule.group,
                    policy: chosen
                });
                switched.push(`${rule.label}->${chosen}(${bestMs}ms)`);
            }
        } else {
            unreachable.push(rule.label);
        }
    }
    return { switched, unreachable };
}

async function runOneClickFix() {
    try {
        const actions = [];

        // 1. 校验并恢复 rule 分流模式
        const outbound = await httpApiAsync("GET", "/v1/outbound");
        if (outbound.mode !== EXPECTED_OUTBOUND_MODE) {
            await httpApiAsync("POST", "/v1/outbound", { mode: EXPECTED_OUTBOUND_MODE });
            actions.push("出站模式已恢复为 RULE");
        }

        // 2. 清空 DNS 缓存并断开旧的僵死连接
        await httpApiAsync("POST", "/v1/dns/flush");
        await httpApiAsync("POST", "/v1/requests/kill");
        actions.push("已清 DNS 与死链");

        // 3. 并发刷新四大地区 Smart 组并执行全节点延迟探测
        const groupsMap = await httpApiAsync("GET", "/v1/policy_groups");
        await Promise.all(
            REGION_GROUP_NAMES.map((gName) => httpApiAsync("POST", "/v1/policy_groups/test", { group_name: gName }))
        );

        const allNodes = collectNodes(groupsMap, REGION_GROUP_NAMES.concat(["Quick", "Staryun"]));
        const testRes = await httpApiAsync("POST", "/v1/policies/test", {
            policy_names: allNodes,
            url: TEST_URL
        });
        const results = testRes.results || testRes || {};
        const latencyMap = {};
        for (const node of allNodes) {
            latencyMap[node] = parseLatencyMs(results[node]);
        }

        // 4. 自动修复所有失效的规则集分流出口
        const { switched, unreachable } = await repairServiceGroups(groupsMap, latencyMap);

        // 5. 校验远程规则集源站（GitHub Raw）是否可正常连通
        const rulesetReachable = await probeUrlAsync(RULESET_PROBE_URL);
        const rulesetStatus = rulesetReachable ? "规则集源站: 连通正常" : "规则集源站: 访问超时，请检查主代理";

        const summaryLines = [actions.join(" | ")];
        if (switched.length > 0) {
            summaryLines.push(`已自动切换: ${switched.join(", ")}`);
        } else if (unreachable.length === 0) {
            summaryLines.push("全部分流策略组出口均畅通，无需切换");
        }
        if (unreachable.length > 0) {
            summaryLines.push(`无可用节点: ${unreachable.join(", ")} (请检查机场订阅或专用 DoH)`);
        }
        summaryLines.push(rulesetStatus);

        const allHealthy = unreachable.length === 0 && rulesetReachable;
        $notification.post(
            allHealthy ? "Surge 一键调通完成" : "Surge 调通完成（存在异常项）",
            switched.length > 0 ? `已切换 ${switched.length} 个策略组` : "已完成缓存清理与链路校验",
            summaryLines.join("\n")
        );

        $done({
            title: allHealthy ? "一键调通 (全部畅通)" : "一键调通 (存在受阻)",
            content: summaryLines.join("\n"),
            icon: allHealthy ? "checkmark.circle.fill" : "exclamationmark.triangle.fill",
            "icon-color": allHealthy ? "#34C759" : "#FF3B30"
        });
    } catch (err) {
        $done({
            title: "一键调通失败",
            content: `执行异常: ${String(err)}`,
            icon: "xmark.circle.fill",
            "icon-color": "#FF3B30"
        });
    }
}

const isManualTrigger = typeof $trigger !== "undefined" && $trigger === "button";
if (isManualTrigger) {
    runOneClickFix();
} else {
    renderIdleState();
}
