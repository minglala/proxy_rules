/**
 * Surge 节点状态概览面板（兼容 policy-path 外部订阅节点）
 * 通过 lineHash 读取 benchmark_results 缓存，手动刷新时通过 /v1/policy_groups/test 触发全量实测
 */

const SOURCE_GROUPS = ["Quick", "Staryun"];
const INFO_NODE_REGEX = /(负载均衡|剩余|流量|过期|重置|官网|套餐)/;
const BUILTIN_POLICIES = new Set(["DIRECT", "REJECT", "REJECT-TINYGIF"]);

const LATENCY_UNTESTED = -2;
const LATENCY_FAILED = -1;
const LATENCY_ALIVE_UNKNOWN_MS = 0;
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
    const msFields = ["lastTestScoreInMS", "scoreInMS", "delay", "latency"];
    for (const key of msFields) {
        if (typeof entry[key] === "number") {
            return normalizeMs(entry[key], false);
        }
    }
    const secFields = ["rtt", "time", "score"];
    for (const key of secFields) {
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
        const members = groupsMap[gName] || [];
        for (const member of members) {
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

function mergeBenchmarkResults(rawRes, nodes, latencyMap) {
    const dict = (rawRes && typeof rawRes.results === "object") ? rawRes.results : rawRes;
    if (!dict || typeof dict !== "object") {
        return;
    }
    for (const node of nodes) {
        const entry = (node.lineHash && dict[node.lineHash] !== undefined)
            ? dict[node.lineHash]
            : dict[node.name];
        const parsed = parseBenchmarkEntry(entry);
        if (parsed !== LATENCY_UNTESTED) {
            updateLatency(latencyMap, node.key, parsed);
        }
    }
}

function mergeGroupTestResults(rawRes, nodes, latencyMap) {
    if (!rawRes || typeof rawRes !== "object") {
        return;
    }
    const byName = new Map();
    const byHash = new Map();
    for (const node of nodes) {
        byHash.set(node.lineHash, node.key);
        if (!byName.has(node.name)) {
            byName.set(node.name, []);
        }
        byName.get(node.name).push(node.key);
    }

    for (const groupPayload of Object.values(rawRes)) {
        const items = Array.isArray(groupPayload && groupPayload.data) ? groupPayload.data : [];
        for (const item of items) {
            const ms = parseBenchmarkEntry(item);
            if (ms === LATENCY_UNTESTED) {
                continue;
            }
            if (item.lineHash && byHash.has(item.lineHash)) {
                updateLatency(latencyMap, byHash.get(item.lineHash), ms);
            } else if (item.name && byName.has(item.name)) {
                for (const key of byName.get(item.name)) {
                    updateLatency(latencyMap, key, ms);
                }
            }
        }
    }
}

async function runGroupTests(groupsMap, groupNames, latencyMap) {
    const testResponses = await Promise.all(
        groupNames.map(async (gName) => {
            const res = await httpApiAsync("POST", "/v1/policy_groups/test", { group_name: gName });
            return { gName, res };
        })
    );

    for (const { gName, res } of testResponses) {
        const availableSet = new Set(Array.isArray(res.available) ? res.available : []);
        const members = groupsMap[gName] || [];
        for (const member of members) {
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
}

async function fetchSelectMap(groupNames) {
    const selectMap = {};
    await Promise.all(
        groupNames.map(async (name) => {
            const encoded = encodeURIComponent(name);
            const res = await httpApiAsync("GET", `/v1/policy_groups/select?group_name=${encoded}`);
            if (res && typeof res.policy === "string" && res.policy.length > 0) {
                selectMap[name] = res.policy;
            }
        })
    );
    return selectMap;
}

function isPolicyAlive(policyName, groupsMap, selectMap, latencyMap, visited = new Set()) {
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

    if (selectMap[policyName]) {
        return isPolicyAlive(selectMap[policyName], groupsMap, selectMap, latencyMap, visited);
    }

    const members = groupsMap[policyName];
    if (Array.isArray(members)) {
        return members.some((m) => {
            if (!m || !m.name || INFO_NODE_REGEX.test(m.name)) {
                return false;
            }
            if (m.isGroup) {
                return isPolicyAlive(m.name, groupsMap, selectMap, latencyMap, new Set(visited));
            }
            const ms = latencyMap[getNodeKey(m)];
            return ms !== undefined && ms >= LATENCY_ALIVE_UNKNOWN_MS;
        });
    }
    return false;
}

function buildRegionSummary(groupsMap, latencyMap) {
    return REGION_GROUPS.map((region) => {
        const nodes = collectNodes(groupsMap, [region.name]);
        let alive = 0;
        let bestMs = Infinity;
        for (const node of nodes) {
            const ms = latencyMap[node.key];
            if (ms !== undefined && ms >= LATENCY_ALIVE_UNKNOWN_MS) {
                alive += 1;
                if (ms > 0 && ms < bestMs) {
                    bestMs = ms;
                }
            }
        }
        const bestText = bestMs < Infinity ? `${bestMs}ms` : (alive > 0 ? "可用" : "失效");
        return `${region.label} ${alive}/${nodes.length}(${bestText})`;
    }).join(" | ");
}

function summarizeNodes(nodes, latencyMap) {
    let aliveCount = 0;
    let failedCount = 0;
    let untestedCount = 0;
    let bestNode = "";
    let bestMs = Infinity;

    for (const node of nodes) {
        const ms = latencyMap[node.key];
        if (ms !== undefined && ms >= LATENCY_ALIVE_UNKNOWN_MS) {
            aliveCount += 1;
            if (ms > 0 && ms < bestMs) {
                bestMs = ms;
                bestNode = node.name;
            }
        } else if (ms === LATENCY_FAILED) {
            failedCount += 1;
        } else {
            untestedCount += 1;
        }
    }
    return { aliveCount, failedCount, untestedCount, bestNode, bestMs };
}

async function main() {
    try {
        const groupsMap = await httpApiAsync("GET", "/v1/policy_groups");
        const regionNames = REGION_GROUPS.map((r) => r.name);
        const scanGroups = SOURCE_GROUPS.concat(regionNames);
        const nodes = collectNodes(groupsMap, scanGroups);

        if (nodes.length === 0) {
            $done({
                title: "节点概览 (无有效节点)",
                content: "未在 Quick 或 Staryun 策略组中检测到有效节点，请检查订阅。",
                icon: "exclamationmark.triangle.fill",
                "icon-color": "#FF3B30"
            });
            return;
        }

        const latencyMap = {};
        const isManualRefresh = typeof $trigger !== "undefined" && $trigger === "button";

        if (isManualRefresh) {
            await runGroupTests(groupsMap, scanGroups, latencyMap);
        }

        let benchRes = await httpApiAsync("GET", "/v1/policies/benchmark_results");
        let groupTestRes = await httpApiAsync("GET", "/v1/policy_groups/test_results");
        mergeBenchmarkResults(benchRes, nodes, latencyMap);
        mergeGroupTestResults(groupTestRes, nodes, latencyMap);

        // 若自动刷新时完全没有命中任何缓存，自动执行一次策略组测试
        let stats = summarizeNodes(nodes, latencyMap);
        if (!isManualRefresh && stats.aliveCount === 0 && stats.failedCount === 0) {
            await runGroupTests(groupsMap, scanGroups, latencyMap);
            benchRes = await httpApiAsync("GET", "/v1/policies/benchmark_results");
            groupTestRes = await httpApiAsync("GET", "/v1/policy_groups/test_results");
            mergeBenchmarkResults(benchRes, nodes, latencyMap);
            mergeGroupTestResults(groupTestRes, nodes, latencyMap);
            stats = summarizeNodes(nodes, latencyMap);
        }

        const allSelectTargets = SERVICE_GROUPS.map((s) => s.name).concat(SOURCE_GROUPS);
        const selectMap = await fetchSelectMap(allSelectTargets);
        const failedServices = SERVICE_GROUPS
            .filter((svc) => !isPolicyAlive(svc.name, groupsMap, selectMap, latencyMap))
            .map((svc) => svc.label);

        const totalCount = nodes.length;
        const countParts = [`总计 ${totalCount}`, `可用 ${stats.aliveCount}`, `失效 ${stats.failedCount}`];
        if (stats.untestedCount > 0) {
            countParts.push(`未测 ${stats.untestedCount}`);
        }
        const bestLine = stats.bestNode
            ? `${stats.bestNode} (${stats.bestMs}ms)`
            : (stats.aliveCount > 0 ? "节点可用 (点击右上角刷新测速)" : "无连通节点");
        const regionLine = buildRegionSummary(groupsMap, latencyMap);
        const serviceLine = failedServices.length === 0
            ? "核心分流: 全部连通"
            : `异常分流: ${failedServices.join(", ")} (建议点击一键调通)`;

        let icon = "checkmark.shield.fill";
        let color = "#34C759";
        if (stats.aliveCount === 0 || failedServices.length > 0) {
            icon = "xmark.shield.fill";
            color = "#FF3B30";
        } else if (stats.aliveCount / totalCount < HEALTHY_RATIO_THRESHOLD) {
            icon = "exclamationmark.shield.fill";
            color = "#FF9500";
        }

        $done({
            title: "节点状态概览",
            content: [countParts.join(" | "), `最优: ${bestLine}`, `地区: ${regionLine}`, serviceLine].join("\n"),
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
