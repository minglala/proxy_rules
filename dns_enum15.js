/**
 * Surge 节点域名枚举 + 自动写入配置 v15
 * 动态生成: 每次运行重新枚举节点域名, 按模块参数配置的策略组名称与专用 DoH 成对分流
 *       (最多 3 组槽位 g1~g3: g<N>_name + g<N>_doh1/g<N>_doh2, 脚本内不硬编码订阅名),
 *       生成 [Host] 指派行并写入配置标记块;
 *       定时自动更新默认关闭(auto_update=off), cron 按配置周期(auto_hours)唤醒,
 *       仅当 auto_update=on 时执行枚举与写入, 否则直接静默退出。面板手动运行不受此限制。
 * 写入通道(仅 MCP): 通过 POST /v1/mcp 调用 get_profile_section / replace_profile_section
 *       (需 http-api-mcp = true), 先 initialize + tools/list 按设备返回的 schema 调工具,
 *       写入后回读校验。
 * 密钥/端口来自模块参数 api_key/api_port, 只存设备本地模块实例。
 */

const MAP_KEY = "dns_enum_map";
const RUNS_KEY = "dns_enum_domain_runs";
// 2026-11-25 两次全量枚举一致确认的机场后缀, 直接信任; 新后缀需满足信任规则才应用
const TRUSTED_SUFFIXES = ["chhbuv.cn", "inba996.com", "myinba55.com", "mcw.gay", "keyapisub.xyz"];
const BLOCK_KEY = "dns_enum_host_block";
const PROBE_URL = "http://cp.cloudflare.com/generate_204";
const PROBE_TIMEOUT_SEC = 3;
const TIME_BUDGET_MS = 200000;
const FALLBACK_GROUP_NAME = "Quick";
const FALLBACK_DOH_SERVERS = [
    "https://alicdn-tbcdn-jdcdn-iycdn.mcw.gay/b13dc6533ab6db6cac6982acccec36e8/dns-query",
    "https://txcdn-tbcdn-bdcdn-ykcdn.mcw.gay/292f105ae785d1845a8799971ac3a14b/dns-query"
];

function getArgParam(text, key) {
    const match = text.match(new RegExp("(?:^|&)" + key + "=([^&]*)"));
    if (!match) return "";
    return match[1].trim().replace(/^["']|["']$/g, "");
}

function isValidDohServer(value) {
    return (
        Boolean(value) &&
        !value.includes("{{{") &&
        !value.includes(",") &&
        /^(?:https?|tls|quic|h3):\/\//i.test(value)
    );
}

function parseGroupConfigs() {
    const groups = [];
    if (typeof $argument !== "undefined" && $argument) {
        const text = String($argument);
        for (const slot of [1, 2, 3]) {
            const name = getArgParam(text, `g${slot}_name`);
            if (!name || name.toLowerCase() === "none" || name.includes("{{{")) continue;
            const servers = [];
            for (const key of [`g${slot}_doh1`, `g${slot}_doh2`]) {
                const value = getArgParam(text, key);
                if (isValidDohServer(value)) {
                    servers.push(value);
                }
            }
            if (servers.length > 0) {
                groups.push({ name, servers });
            }
        }
    }
    if (groups.length > 0) return groups;
    return [{ name: FALLBACK_GROUP_NAME, servers: FALLBACK_DOH_SERVERS.slice() }];
}

const GROUP_CONFIGS = parseGroupConfigs();
const DEFAULT_GROUP = GROUP_CONFIGS[0];
const ALL_GROUP_SERVERS = GROUP_CONFIGS.reduce((acc, g) => acc.concat(g.servers), []);
const MIN_SUFFIX_COUNT = 2;
const MAX_PANEL_DOMAINS = 30;
const MARK_BEGIN = "# >>> proxy-dns-auto >>>";
const MARK_END = "# <<< proxy-dns-auto <<<";

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

function matchGroupName(rawName, groupConfigs) {
    const trimmed = typeof rawName === "string" ? rawName.trim() : "";
    if (!trimmed) return null;
    const lower = trimmed.toLowerCase();
    for (const cfg of groupConfigs) {
        const cfgName = cfg && typeof cfg.name === "string" ? cfg.name.trim() : "";
        if (cfgName && lower === cfgName.toLowerCase()) {
            return { name: cfg.name, exact: true };
        }
    }
    for (const cfg of groupConfigs) {
        const cfgName = cfg && typeof cfg.name === "string" ? cfg.name.trim() : "";
        if (!cfgName) continue;
        const cfgLower = cfgName.toLowerCase();
        if (lower.includes(cfgLower) || cfgLower.includes(lower)) {
            return { name: cfg.name, exact: false };
        }
    }
    return null;
}

function buildSubMaps(policiesRes, groupConfigs) {
    const byIdentifier = new Map();
    const byName = new Map();
    if (!policiesRes || typeof policiesRes !== "object" || !Array.isArray(groupConfigs) || groupConfigs.length === 0) {
        return { byIdentifier, byName };
    }
    const matchedGroups = [];
    for (const [key, value] of Object.entries(policiesRes)) {
        if (!/group/i.test(key) || !Array.isArray(value)) continue;
        for (const groupObj of value) {
            if (!groupObj || typeof groupObj !== "object") continue;
            const match = matchGroupName(groupObj.name, groupConfigs);
            if (!match) continue;
            matchedGroups.push({ groupObj, groupName: match.name, exact: match.exact });
        }
    }
    matchedGroups.sort((a, b) => Number(b.exact) - Number(a.exact));
    for (const { groupObj, groupName } of matchedGroups) {
        const memberLists = [];
        if (Array.isArray(groupObj.policies)) memberLists.push(groupObj.policies);
        if (Array.isArray(groupObj.members)) memberLists.push(groupObj.members);
        for (const list of memberLists) {
            for (const member of list) {
                if (typeof member === "string") {
                    const trimmed = member.trim();
                    if (trimmed) {
                        if (!byName.has(member)) byName.set(member, groupName);
                        if (trimmed !== member && !byName.has(trimmed)) byName.set(trimmed, groupName);
                    }
                } else if (member && typeof member === "object") {
                    if (typeof member.name === "string") {
                        const trimmed = member.name.trim();
                        if (trimmed) {
                            if (!byName.has(member.name)) byName.set(member.name, groupName);
                            if (trimmed !== member.name && !byName.has(trimmed)) byName.set(trimmed, groupName);
                        }
                    }
                    if (typeof member.identifier === "string") {
                        const trimmed = member.identifier.trim();
                        if (trimmed) {
                            if (!byIdentifier.has(member.identifier)) byIdentifier.set(member.identifier, groupName);
                            if (trimmed !== member.identifier && !byIdentifier.has(trimmed)) byIdentifier.set(trimmed, groupName);
                        }
                    }
                }
            }
        }
    }
    return { byIdentifier, byName };
}

function resolveDomainGroup(nodes, nodeSubMap, groupConfigs, defaultGroupName) {
    const votes = new Map();
    if (Array.isArray(nodes)) {
        for (const node of nodes) {
            const sub = nodeSubMap.get(node) || "unknown";
            if (sub === "unknown") continue;
            votes.set(sub, (votes.get(sub) || 0) + 1);
        }
    }
    if (votes.size === 0) return defaultGroupName;
    let winner = defaultGroupName;
    let bestCount = 0;
    for (const cfg of groupConfigs) {
        const count = votes.get(cfg.name) || 0;
        if (count > bestCount) {
            bestCount = count;
            winner = cfg.name;
        }
    }
    return bestCount > 0 ? winner : defaultGroupName;
}

function buildHostLines(domainGroupList) {
    const groupServerMap = new Map();
    for (const cfg of GROUP_CONFIGS) {
        groupServerMap.set(cfg.name, cfg.servers.join(","));
    }
    const defaultServerList = DEFAULT_GROUP.servers.join(",");
    const serversForGroup = (groupName) => groupServerMap.get(groupName) || defaultServerList;

    const bootstrapList = BOOTSTRAP_SERVERS.join(",");
    const dohHostSuffixes = new Set();
    for (const server of ALL_GROUP_SERVERS) {
        const host = extractHost(server);
        if (host && !isIpLike(host)) dohHostSuffixes.add(regDomainOf(host));
    }
    const hostLines = [];
    for (const suffix of Array.from(dohHostSuffixes).sort()) {
        hostLines.push(`*.${suffix} = server:${bootstrapList}`);
    }
    const cluster = new Map();
    for (const item of domainGroupList) {
        const domain = item.domain;
        const effectiveGroup = groupServerMap.has(item.group) ? item.group : DEFAULT_GROUP.name;
        const rd = regDomainOf(domain);
        if (!cluster.has(rd)) {
            cluster.set(rd, { count: 0, groups: new Set() });
        }
        const entry = cluster.get(rd);
        entry.count += 1;
        entry.groups.add(effectiveGroup);
    }
    const covered = new Set();
    const suffixes = Array.from(cluster.entries()).sort((a, b) => b[1].count - a[1].count);
    for (const [suffix, info] of suffixes) {
        if (info.count >= MIN_SUFFIX_COUNT && info.groups.size === 1 && !dohHostSuffixes.has(suffix)) {
            const [onlyGroup] = info.groups;
            hostLines.push(`*.${suffix} = server:${serversForGroup(onlyGroup)}`);
            covered.add(suffix);
        }
    }
    for (const item of domainGroupList) {
        const domain = item.domain;
        const rd = regDomainOf(domain);
        if (dohHostSuffixes.has(rd)) continue;
        const serverList = serversForGroup(item.group);
        if (domain === rd) {
            hostLines.push(`${domain} = server:${serverList}`);
        } else if (!covered.has(rd)) {
            hostLines.push(`${domain} = server:${serverList}`);
        }
    }
    return hostLines;
}

function parseSectionToolText(text) {
    const raw = typeof text === "string" ? text : String(text || "");
    try {
        const parsed = raw ? JSON.parse(raw) : null;
        if (parsed && typeof parsed === "object" && typeof parsed.content === "string") {
            return {
                content: parsed.content,
                revision: parsed.revision != null ? String(parsed.revision) : undefined
            };
        }
    } catch (_) {}
    const lines = raw.replace(/\r\n?/g, "\n").split("\n");
    let i = 0;
    let revision;
    while (i < lines.length && /^(Section|File|Editable|Revision|Lines):/.test(lines[i])) {
        const revMatch = lines[i].match(/^Revision:\s*(\S+)/);
        if (revMatch) revision = revMatch[1];
        i += 1;
    }
    if (i === 0) {
        return { content: raw, revision: undefined };
    }
    if (i < lines.length && lines[i].trim() === "") {
        i += 1;
    }
    return { content: lines.slice(i).join("\n"), revision };
}

function normalizeSectionContent(text) {
    const linesArr = String(text || "").replace(/\r\n?/g, "\n").split("\n");
    const filtered = linesArr.filter((line) => line.trim().toLowerCase() !== "[host]");
    while (filtered.length > 0 && filtered[0].trim() === "") filtered.shift();
    while (filtered.length > 0 && filtered[filtered.length - 1].trim() === "") filtered.pop();
    return filtered.join("\n");
}

function stripAutoBlock(content) {
    const normalized = String(content || "").replace(/\r\n/g, "\n");
    const linesArr = normalized.split("\n");
    const beginIdx = linesArr.findIndex((l) => l.trim() === MARK_BEGIN);
    const endIdx = linesArr.findIndex((l) => l.trim() === MARK_END);
    if (beginIdx < 0 || endIdx < beginIdx) {
        while (linesArr.length > 0 && linesArr[linesArr.length - 1].trim() === "") linesArr.pop();
        return linesArr.join("\n");
    }
    const kept = linesArr.slice(0, beginIdx).concat(linesArr.slice(endIdx + 1));
    while (kept.length > 0 && kept[kept.length - 1].trim() === "") kept.pop();
    return kept.join("\n");
}

function discoverHttpApi() {
    let key = "";
    let port = "6171";
    if (typeof $argument !== "undefined" && $argument) {
        const text = String($argument);
        const km = text.match(/(?:^|&)api_key=([^&]*)/);
        if (km) key = km[1].trim();
        const pm = text.match(/(?:^|&)api_port=([^&]*)/);
        if (pm && pm[1].trim()) port = pm[1].trim();
    }
    if (!key) return { ok: false, reason: "模块参数 api_key 未填写" };
    return { ok: true, cfg: { key, port } };
}

function isAutoUpdateEnabled() {
    if (typeof $argument !== "undefined" && $argument) {
        const text = String($argument);
        const am = text.match(/(?:^|&)auto_update=([^&]*)/);
        if (am && am[1].trim() === "on") return true;
    }
    return false;
}

function extRawFactory(httpApiCfg) {
    const base = `http://127.0.0.1:${httpApiCfg.port}`;
    return function extRaw(method, path, bodyObj, extraHeaders) {
        return new Promise((resolve) => {
            const headers = Object.assign(
                { "X-Key": httpApiCfg.key, "Content-Type": "application/json" },
                extraHeaders || {}
            );
            const options = { url: base + path, headers, timeout: 20 };
            const done = (resp, data) => {
                const status = resp && typeof resp.status === "number" ? resp.status : 0;
                let json = null;
                try {
                    json = data ? JSON.parse(data) : null;
                } catch (_) {}
                resolve({ status, json, raw: typeof data === "string" ? data : "" });
            };
            if (method === "GET") {
                $httpClient.get(options, (err, resp, data) => done(resp, data));
            } else {
                options.body = typeof bodyObj === "string" ? bodyObj : JSON.stringify(bodyObj || {});
                $httpClient.post(options, (err, resp, data) => done(resp, data));
            }
        });
    };
}

function briefResult(r) {
    if (!r) return "无响应";
    if (r.json && r.json.error) return `HTTP ${r.status} error=${String(r.json.error).slice(0, 60)}`;
    if (r.status >= 200 && r.status < 300) return `HTTP ${r.status} OK`;
    const raw = (r.raw || "").replace(/\s+/g, " ").slice(0, 60);
    return `HTTP ${r.status || "?"} ${raw}`;
}

async function applyToProfile(hostLines) {
    if (hostLines.length === 0) {
        return { ok: false, reason: "没有可应用的指派行" };
    }
    const blockText = [MARK_BEGIN, `# 自动生成 ${formatTimeNow()}, 来源: 节点域名枚举`, ...hostLines, MARK_END].join("\n");
    const discovered = discoverHttpApi();
    if (!discovered.ok) {
        return { ok: false, reason: discovered.reason };
    }
    const extRaw = extRawFactory(discovered.cfg);
    const report = [];

    // ---- MCP 工具 ----
    let mcpId = 0;
    const mcpCall = async (method, params) => {
        mcpId += 1;
        const payload = { jsonrpc: "2.0", id: mcpId, method };
        if (params) payload.params = params;
        return extRaw("POST", "/v1/mcp", payload, { Accept: "application/json, text/event-stream" });
    };
    const init = await mcpCall("initialize", {
        protocolVersion: "2025-03-26",
        capabilities: {},
        clientInfo: { name: "dns-enum", version: "15" }
    });
    report.push(`MCP初始化: ${briefResult(init)}`);
    if (init.status === 403) {
        report.push("MCP未开启或功能未解锁: 需 http-api-mcp = true");
        return { ok: false, reason: report.join("; ") };
    }
    if (init.json && !init.json.error) {
        const list = await mcpCall("tools/list", {});
        const tools = list.json && list.json.result && Array.isArray(list.json.result.tools) ? list.json.result.tools : [];
        const getTool = tools.find((t) => t && t.name === "get_profile_section");
        const putTool = tools.find((t) => t && t.name === "replace_profile_section");
        if (!getTool || !putTool) {
            report.push(`MCP工具列表 ${tools.length} 个, 未找到配置段工具`);
            return { ok: false, reason: report.join("; ") };
        }
        const callTool = async (tool, args) => {
            const r = await mcpCall("tools/call", { name: tool.name, arguments: args });
            if (!r.json || r.json.error) return { ok: false, reason: briefResult(r) };
            const result = r.json.result || {};
            if (result.isError) {
                const txt = result.content && result.content[0] ? String(result.content[0].text || "") : "";
                return { ok: false, reason: `工具错误: ${txt.slice(0, 400)}` };
            }
            const text = result.content && result.content[0] && typeof result.content[0].text === "string" ? result.content[0].text : "";
            let parsed = null;
            try {
                parsed = text ? JSON.parse(text) : null;
            } catch (_) {}
            return { ok: true, text, parsed };
        };
        const pickArg = (schema, patterns, fallback) => {
            const props = schema && schema.inputSchema && schema.inputSchema.properties ? Object.keys(schema.inputSchema.properties) : [];
            for (const pattern of patterns) {
                const hit = props.find((k) => pattern.test(k));
                if (hit) return hit;
            }
            return fallback;
        };
        const nameKey = pickArg(getTool, [/^name$/i, /section/i], "name");
        const gotArgs = {};
        gotArgs[nameKey] = "Host";
        const got = await callTool(getTool, gotArgs);
        if (!got.ok) {
            report.push(`MCP读段: ${got.reason}`);
            return { ok: false, reason: report.join("; ") };
        }
        const { content: oldContent, revision } = parseSectionToolText(got.text);
        const normalizedOld = normalizeSectionContent(oldContent || "");
        const cleaned = stripAutoBlock(normalizedOld);
        const newContentLines = ((cleaned ? cleaned + "\n" : "") + blockText)
            .replace(/\r\n?/g, "\n")
            .split("\n")
            .filter((line) => !/^\[[^\[\]=]+\]$/.test(line.trim()));
        while (newContentLines.length > 0 && newContentLines[0].trim() === "") newContentLines.shift();
        while (newContentLines.length > 0 && newContentLines[newContentLines.length - 1].trim() === "") newContentLines.pop();
        const newContent = newContentLines.join("\n");
        const putNameKey = pickArg(putTool, [/^name$/i, /section/i], "name");
        const putContentKey = pickArg(putTool, [/content/i, /text/i], "content");
        const putRevisionKey = pickArg(putTool, [/revision/i], "revision");
        const putArgs = {};
        putArgs[putNameKey] = "Host";
        putArgs[putContentKey] = newContent;
        if (revision) putArgs[putRevisionKey] = revision;
        const put = await callTool(putTool, putArgs);
        if (!put.ok) {
            report.push(`MCP写入: ${put.reason}`);
            report.push(`GET样本: ${String(got.text || "").slice(0, 150)}`);
            return { ok: false, reason: report.join("; ") };
        }
        const verify = await callTool(getTool, gotArgs);
        if (verify.ok) {
            const { content: vContent } = parseSectionToolText(verify.text);
            if (typeof vContent === "string" && vContent.includes(MARK_BEGIN)) {
                return { ok: true, reason: "MCP 配置段工具" };
            }
        }
        report.push("MCP写入后回读校验未通过");
        return { ok: false, reason: report.join("; ") };
    }

    return { ok: false, reason: report.join("; ") || "MCP 调用失败" };
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
    if (typeof $cronexp !== "undefined" && !isAutoUpdateEnabled()) {
        $done();
        return;
    }
    const lines = [];
    try {
        let policiesRes = await httpApiAsync("GET", "/v1/policies", { include_external: "true" });
        if (!policiesRes || !Array.isArray(policiesRes["external-policies"])) {
            policiesRes = await httpApiAsync("GET", "/v1/policies?include_external=true");
        }
        const external = policiesRes && Array.isArray(policiesRes["external-policies"]) ? policiesRes["external-policies"] : [];
        const { byIdentifier, byName } = buildSubMaps(policiesRes, GROUP_CONFIGS);
        const groupNodeCounts = new Map();
        for (const cfg of GROUP_CONFIGS) groupNodeCounts.set(cfg.name, 0);
        let unknownNodeCount = 0;
        const nodeSubMap = new Map();
        for (const item of external) {
            const name = item && typeof item.name === "string" ? item.name : "";
            const identifier = item && typeof item.identifier === "string" ? item.identifier : "";
            if (!identifier) continue;
            const sub = byIdentifier.get(identifier) || byName.get(name) || "unknown";
            if (name) nodeSubMap.set(name, sub);
            if (groupNodeCounts.has(sub)) {
                groupNodeCounts.set(sub, groupNodeCounts.get(sub) + 1);
            } else {
                unknownNodeCount += 1;
            }
        }

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

        const groupDomainCounts = new Map();
        for (const cfg of GROUP_CONFIGS) groupDomainCounts.set(cfg.name, 0);
        const domainGroupList = distinctDomains.map((domain) => {
            const group = resolveDomainGroup(
                domainNodes.get(domain),
                nodeSubMap,
                GROUP_CONFIGS,
                DEFAULT_GROUP.name
            );
            groupDomainCounts.set(group, (groupDomainCounts.get(group) || 0) + 1);
            return { domain, group };
        });

        const hostLines = buildHostLines(domainGroupList);
        try {
            $persistentStore.write(hostLines.join("\n"), BLOCK_KEY);
        } catch (_) {}

        const applied = await applyToProfile(hostLines);

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
        for (const cfg of GROUP_CONFIGS) {
            const dCount = groupDomainCounts.get(cfg.name) || 0;
            lines.push(`${cfg.name} 专用 DNS: ${cfg.servers.length} 台, 域名 ${dCount} 个`);
        }
        const subParts = GROUP_CONFIGS.map((cfg) => `${cfg.name} 节点 ${groupNodeCounts.get(cfg.name) || 0} 个`);
        subParts.push(`未识别 ${unknownNodeCount} 个`);
        lines.push(`订阅分组: ${subParts.join(" / ")}`);
        if (byIdentifier.size === 0 && byName.size === 0) {
            lines.push(`未识别订阅分组, 全部按 ${DEFAULT_GROUP.name} 处理`);
        }
        if (applied.ok) {
            lines.push(`✅ 已自动应用: ${hostLines.length} 条指派已写入配置 [Host] 段并回读校验通过 (通道: ${applied.reason})`);
        } else {
            lines.push(`⚠️ 自动应用失败: ${applied.reason}`);
            lines.push("失败原因见上, 截图发我即可");
        }
        lines.push(`检查时间: ${formatTimeNow()}`);
        if (typeof $cronexp !== "undefined") {
            $done();
            return;
        }
        $done({
            title: `节点域名枚举v15 (${formatTimeNow()})`,
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
