/**
 * Surge 节点状态概览面板
 * 统计 Quick 与 Staryun 节点总数、可用/失效数、全局最优节点及核心分流组健康度
 */

const TEST_URL = "http://cp.cloudflare.com/generate_204";
const SOURCE_GROUPS = ["Quick", "Staryun"];
const INFO_NODE_REGEX = /(负载均衡|剩余|流量|过期|重置|官网|套餐)/;
const BUILTIN_POLICIES = new Set(["DIRECT", "REJECT", "REJECT-TINYGIF"]);
const INVALID_LATENCY = -1;
const SECONDS_THRESHOLD = 10;
const SECONDS_TO_MS = 1000;
const HEALTHY_RATIO_THRESHOLD = 0.5;

const REGION_GROUPS = [
    { name: "🇭🇰香港", label: "香港" },
    { name: "🇸🇬新加坡", label: "新加坡" },
    { name: "🇯🇵日服", label: "日本" },
    { name: "🇺🇲美服", label: "美国" }
];

const SERVICE_GROUPS = [
    { name: "Proxy", label: "主代理" },
    { name: "📟智能助理", label: "AI" },
    { name: "Google", label: "Google" },
    { name: "▶️Youtube", label: "YouTube" },
    { name: "Social Media", label: "社交" },
    { name: "Spotify", label: "Spotify" }
];

function httpApiAsync(method, path, body = {}) {
    return new Promise((resolve) => {
        $httpAPI(method, path, body, (res) => resolve(res || {}));
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

function collectRealNodes(groupsMap, groupNames) {
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

function isPolicyAlive(policyName, groupsMap, latencyMap, visited = new Set()) {
    if (!policyName || visited.has(policyName)) {
        return false;
    }
    if (policyName === "DIRECT") {
        return true;
    }
    if (BUILTIN_POLICIES.has(policyName)) {
        return false;
    }
    visited.add(policyName);
    const members = groupsMap[policyName];
    if (Array.isArray(members)) {
        return members.some((m) => m && !INFO_NODE_REGEX.test(m.name) && isPolicyAlive(m.name, groupsMap, latencyMap, visited));
    }
    return (latencyMap[policyName] || INVALID_LATENCY) > 0;
}

function buildRegionSummary(groupsMap, latencyMap) {
    return REGION_GROUPS.map((region) => {
        const nodes = collectRealNodes(groupsMap, [region.name]);
        let alive = 0;
        let bestMs = Infinity;
        for (const node of nodes) {
            const ms = latencyMap[node] || INVALID_LATENCY;
            if (ms > 0) {
                alive += 1;
                if (ms < bestMs) {
                    bestMs = ms;
                }
            }
        }
        const bestText = bestMs < Infinity ? `${bestMs}ms` : "失效";
        return `${region.label} ${alive}/${nodes.length}(${bestText})`;
    }).join(" | ");
}

async function checkServiceGroups(groupsMap, latencyMap) {
    const failedLabels = [];
    for (const svc of SERVICE_GROUPS) {
        const encoded = encodeURIComponent(svc.name);
        const selRes = await httpApiAsync("GET", `/v1/policy_groups/select?group_name=${encoded}`);
        const current = selRes.policy || "";
        if (!isPolicyAlive(current, groupsMap, latencyMap)) {
            failedLabels.push(svc.label);
        }
    }
    return failedLabels;
}

async function main() {
    try {
        const groupsMap = await httpApiAsync("GET", "/v1/policy_groups");
        const allGroupsToScan = SOURCE_GROUPS.concat(REGION_GROUPS.map((r) => r.name));
        const uniqueNodes = collectRealNodes(groupsMap, allGroupsToScan);

        if (uniqueNodes.length === 0) {
            $done({
                title: "节点概览 (无可用节点)",
                content: "未在 Quick 或 Staryun 策略组中检测到有效节点，请检查订阅更新。",
                icon: "exclamationmark.triangle.fill",
                "icon-color": "#FF3B30"
            });
            return;
        }

        const testRes = await httpApiAsync("POST", "/v1/policies/test", {
            policy_names: uniqueNodes,
            url: TEST_URL
        });
        const results = testRes.results || testRes || {};

        const latencyMap = {};
        let aliveCount = 0;
        let bestNode = "";
        let bestMs = Infinity;

        for (const node of uniqueNodes) {
            const ms = parseLatencyMs(results[node]);
            latencyMap[node] = ms;
            if (ms > 0) {
                aliveCount += 1;
                if (ms < bestMs) {
                    bestMs = ms;
                    bestNode = node;
                }
            }
        }

        const totalCount = uniqueNodes.length;
        const failedCount = totalCount - aliveCount;
        const regionLine = buildRegionSummary(groupsMap, latencyMap);
        const failedServices = await checkServiceGroups(groupsMap, latencyMap);
        const bestLine = bestNode ? `${bestNode} (${bestMs}ms)` : "无连通节点";
        const serviceLine = failedServices.length === 0
            ? "核心分流: 全部连通"
            : `异常分流: ${failedServices.join(", ")} (建议点击一键调通)`;

        let icon = "checkmark.shield.fill";
        let color = "#34C759";
        if (aliveCount === 0 || failedServices.length > 0) {
            icon = "xmark.shield.fill";
            color = "#FF3B30";
        } else if (aliveCount / totalCount < HEALTHY_RATIO_THRESHOLD) {
            icon = "exclamationmark.shield.fill";
            color = "#FF9500";
        }

        const content = [
            `总计 ${totalCount} | 可用 ${aliveCount} | 失效 ${failedCount}`,
            `最优: ${bestLine}`,
            `地区: ${regionLine}`,
            serviceLine
        ].join("\n");

        $done({
            title: "节点状态概览",
            content,
            icon,
            "icon-color": color
        });
    } catch (err) {
        $done({
            title: "节点概览异常",
            content: `统计脚本执行失败: ${String(err)}`,
            icon: "exclamationmark.triangle.fill",
            "icon-color": "#FF3B30"
        });
    }
}

main();
