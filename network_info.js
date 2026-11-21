/**
 * Surge 增强版网络信息诊断面板（双栈完整展示）
 * 展示内网信息、国内直连 IPv4/IPv6、代理节点 IPv4/IPv6、落地属性、当前策略链路及双通道延迟
 */

const POLICY_DIRECT = "DIRECT";
const POLICY_PROXY = "Proxy";

const DIRECT_IPV4_PRIMARY_URL = "https://myip.ipip.net/json";
const DIRECT_IPV4_FALLBACK_URL = "https://forge.speedtest.cn/api/location/info";
const DIRECT_IPV6_PRIMARY_URL = "https://6.ipw.cn";
const DIRECT_IPV6_FALLBACK_URL = "https://api6.ipify.org";

const PROXY_IPV4_PRIMARY_URL = "http://ip-api.com/json/?fields=status,countryCode,city,isp,org,hosting,proxy,query";
const PROXY_IPV4_FALLBACK_URL = "https://api.ip.sb/geoip";
const PROXY_IPV6_PRIMARY_URL = "https://api6.ipify.org";
const PROXY_IPV6_FALLBACK_URL = "https://ipv6.icanhazip.com";

const DIRECT_PING_URL = "http://connectivitycheck.platform.hicloud.com/generate_204";
const PROXY_PING_URL = "http://cp.cloudflare.com/generate_204";

const REQUEST_TIMEOUT_SEC = 5;
const HTTP_OK_MIN = 200;
const HTTP_OK_MAX = 300;
const MAX_POLICY_DEPTH = 3;
const LATENCY_INVALID = -1;
const IPV6_MAX_LENGTH = 45;
const IPV6_LINK_LOCAL_PREFIX = "fe80:";
const IPV6_PATTERN = /^[0-9a-fA-F:.]+$/;

const RADIO_LABELS = {
    CTRadioAccessTechnologyNR: "5G SA",
    CTRadioAccessTechnologyNRNSA: "5G NSA",
    CTRadioAccessTechnologyLTE: "4G LTE",
    CTRadioAccessTechnologyWCDMA: "3G",
    CTRadioAccessTechnologyHSDPA: "3G",
    CTRadioAccessTechnologyHSUPA: "3G",
    CTRadioAccessTechnologyCDMAEVDORev0: "3G",
    CTRadioAccessTechnologyCDMAEVDORevA: "3G",
    CTRadioAccessTechnologyCDMAEVDORevB: "3G",
    CTRadioAccessTechnologyeHRPD: "3G",
    CTRadioAccessTechnologyEdge: "2G",
    CTRadioAccessTechnologyGPRS: "2G",
    CTRadioAccessTechnologyCDMA1x: "2G"
};

const CARRIER_LABELS = {
    "460-00": "中国移动",
    "460-02": "中国移动",
    "460-04": "中国移动",
    "460-07": "中国移动",
    "460-08": "中国移动",
    "460-01": "中国联通",
    "460-06": "中国联通",
    "460-09": "中国联通",
    "460-03": "中国电信",
    "460-05": "中国电信",
    "460-11": "中国电信",
    "460-15": "中国广电"
};

function httpApiAsync(method, path, body = {}) {
    return new Promise((resolve) => {
        $httpAPI(method, path, body, (res) => resolve(res || {}));
    });
}

function httpGetTimed(url, policy) {
    return new Promise((resolve) => {
        const startTime = Date.now();
        const opts = { url, timeout: REQUEST_TIMEOUT_SEC };
        if (policy) {
            opts.policy = policy;
        }
        $httpClient.get(opts, (error, response, data) => {
            const elapsed = Date.now() - startTime;
            const status = response ? response.status : 0;
            const ok = !error && status >= HTTP_OK_MIN && status < HTTP_OK_MAX;
            resolve({
                ok,
                status,
                ms: ok ? elapsed : LATENCY_INVALID,
                body: typeof data === "string" ? data : ""
            });
        });
    });
}

function isValidIpv6(rawText) {
    const trimmed = (rawText || "").trim();
    if (!trimmed || trimmed.length > IPV6_MAX_LENGTH || !trimmed.includes(":")) {
        return false;
    }
    return IPV6_PATTERN.test(trimmed);
}

async function fetchIpv6Address(primaryUrl, fallbackUrl, policy) {
    const primary = await httpGetTimed(primaryUrl, policy);
    if (primary.ok && isValidIpv6(primary.body)) {
        return primary.body.trim();
    }
    const fallback = await httpGetTimed(fallbackUrl, policy);
    if (fallback.ok && isValidIpv6(fallback.body)) {
        return fallback.body.trim();
    }
    return "";
}

function parseDirectIpip(body) {
    try {
        const json = JSON.parse(body);
        if (json.ret !== "ok" || !json.data || !json.data.ip) {
            return null;
        }
        const loc = Array.isArray(json.data.location) ? json.data.location : [];
        const province = loc[1] || "";
        const city = loc[2] || "";
        const isp = loc[4] || "";
        const region = (city && city !== province) ? `${province}${city}` : (province || loc[0] || "");
        return { ok: true, ip: json.data.ip, detail: [region, isp].filter(Boolean).join(" ") };
    } catch (_) {
        return null;
    }
}

function parseDirectSpeedtest(body) {
    try {
        const json = JSON.parse(body);
        if (!json || !json.ip) {
            return null;
        }
        const province = json.province || "";
        const city = json.city || "";
        const region = (city && city !== province) ? `${province}${city}` : (province || json.country || "");
        return { ok: true, ip: json.ip, detail: [region, json.isp || ""].filter(Boolean).join(" ") };
    } catch (_) {
        return null;
    }
}

async function fetchDirectInfo() {
    const primary = await httpGetTimed(DIRECT_IPV4_PRIMARY_URL, POLICY_DIRECT);
    if (primary.ok) {
        const parsed = parseDirectIpip(primary.body);
        if (parsed) {
            return parsed;
        }
    }
    const fallback = await httpGetTimed(DIRECT_IPV4_FALLBACK_URL, POLICY_DIRECT);
    if (fallback.ok) {
        const parsed = parseDirectSpeedtest(fallback.body);
        if (parsed) {
            return parsed;
        }
    }
    return { ok: false, ip: "", detail: "" };
}

function parseProxyIpApi(body) {
    try {
        const json = JSON.parse(body);
        if (json.status !== "success" || !json.query) {
            return null;
        }
        let typeTag = "非机房";
        if (json.hosting) {
            typeTag = "机房";
        } else if (json.proxy) {
            typeTag = "代理";
        }
        const region = [json.countryCode, json.city].filter(Boolean).join(" ");
        return {
            ok: true,
            ip: json.query,
            region,
            isp: json.isp || json.org || "未知 ISP",
            typeTag
        };
    } catch (_) {
        return null;
    }
}

function parseProxyIpSb(body) {
    try {
        const json = JSON.parse(body);
        if (!json || !json.ip) {
            return null;
        }
        const region = [json.country_code, json.city].filter(Boolean).join(" ");
        return {
            ok: true,
            ip: json.ip,
            region,
            isp: json.isp || json.organization || "未知 ISP",
            typeTag: ""
        };
    } catch (_) {
        return null;
    }
}

async function fetchProxyInfo(proxyPolicy) {
    const primary = await httpGetTimed(PROXY_IPV4_PRIMARY_URL, proxyPolicy);
    if (primary.ok) {
        const parsed = parseProxyIpApi(primary.body);
        if (parsed) {
            return parsed;
        }
    }
    const fallback = await httpGetTimed(PROXY_IPV4_FALLBACK_URL, proxyPolicy);
    if (fallback.ok) {
        const parsed = parseProxyIpSb(fallback.body);
        if (parsed) {
            return parsed;
        }
    }
    return { ok: false, ip: "", region: "", isp: "", typeTag: "" };
}

async function resolvePolicyRoute(groupsMap, rootGroup) {
    if (!groupsMap || !groupsMap[rootGroup]) {
        return "";
    }
    const chain = [rootGroup];
    let current = rootGroup;
    for (let depth = 0; depth < MAX_POLICY_DEPTH; depth += 1) {
        const encoded = encodeURIComponent(current);
        const res = await httpApiAsync("GET", `/v1/policy_groups/select?group_name=${encoded}`);
        const next = res && typeof res.policy === "string" ? res.policy : "";
        if (!next || chain.includes(next)) {
            break;
        }
        chain.push(next);
        if (!groupsMap[next]) {
            break;
        }
        current = next;
    }
    return chain.join(" -> ");
}

function getLocalNetworkMeta() {
    const net = typeof $network === "object" && $network ? $network : {};
    const wifiSsid = (net.wifi && net.wifi.ssid) ? net.wifi.ssid : "";
    const v4 = net.v4 || {};
    const v6 = net.v6 || {};
    const cellular = net["cellular-data"] || {};

    const isWifi = Boolean(wifiSsid);
    const radioText = RADIO_LABELS[cellular.radio] || "蜂窝数据";
    const carrierText = CARRIER_LABELS[cellular.carrier] || "";
    const netLabel = isWifi ? wifiSsid : [carrierText, radioText].filter(Boolean).join(" ");

    const ipText = v4.primaryAddress || "未分配";
    const routerText = v4.primaryRouter || "";
    const rawV6 = (v6.primaryAddress && typeof v6.primaryAddress === "string") ? v6.primaryAddress.trim() : "";
    const localV6 = (rawV6 && !rawV6.toLowerCase().startsWith(IPV6_LINK_LOCAL_PREFIX)) ? rawV6 : "";

    const lanLine = isWifi && routerText
        ? `内网: ${ipText} / ${routerText}`
        : `本机: ${ipText}${v4.primaryInterface ? ` (${v4.primaryInterface})` : ""}`;

    return { isWifi, netLabel, lanLine, localV6 };
}

function formatPing(ms) {
    return ms > 0 ? `${ms}ms` : "超时";
}

function formatTimeNow() {
    const now = new Date();
    const hh = String(now.getHours()).padStart(2, "0");
    const mm = String(now.getMinutes()).padStart(2, "0");
    const ss = String(now.getSeconds()).padStart(2, "0");
    return `${hh}:${mm}:${ss}`;
}

function pickPanelStyle(isWifi, directOk, proxyOk, isDirectMode) {
    const icon = isWifi ? "wifi" : "antenna.radiowaves.left.and.right";
    if (!directOk && !proxyOk) {
        return { icon: "wifi.exclamationmark", color: "#FF3B30" };
    }
    if (isDirectMode) {
        return { icon, color: directOk ? "#007AFF" : "#FF9500" };
    }
    if (directOk && proxyOk) {
        return { icon, color: "#34C759" };
    }
    return { icon, color: "#FF9500" };
}

function buildPanelLines(data) {
    const directV4Line = data.directInfo.ok
        ? `直连v4: ${data.directInfo.ip}${data.directInfo.detail ? ` (${data.directInfo.detail})` : ""}`
        : "直连v4: 探测失败";

    let directV6Line = "直连v6: 未连通";
    if (data.directV6) {
        directV6Line = `直连v6: ${data.directV6}`;
    } else if (data.localMeta.localV6) {
        directV6Line = `直连v6: 未通 (网卡: ${data.localMeta.localV6})`;
    }

    const proxyTags = [data.proxyInfo.region, data.proxyInfo.typeTag].filter(Boolean).join(" · ");
    const proxyV4Line = data.proxyInfo.ok
        ? `节点v4: ${data.proxyInfo.ip}${proxyTags ? ` (${proxyTags})` : ""}`
        : "节点v4: 探测失败";
    const proxyV6Line = data.proxyV6 ? `节点v6: ${data.proxyV6}` : "节点v6: 不支持或未开启";

    const ispParts = [];
    if (data.proxyInfo.ok && data.proxyInfo.isp) {
        ispParts.push(`落地: ${data.proxyInfo.isp}`);
    }
    if (data.routeText) {
        ispParts.push(`策略: ${data.routeText}`);
    }

    const lines = [data.localMeta.lanLine, directV4Line, directV6Line, proxyV4Line, proxyV6Line];
    if (ispParts.length > 0) {
        lines.push(ispParts.join(" | "));
    }
    lines.push(`延迟: 国内 ${formatPing(data.directPing.ms)} | 代理 ${formatPing(data.proxyPing.ms)}`);
    return lines;
}

async function main() {
    try {
        const localMeta = getLocalNetworkMeta();
        const [outboundRes, groupsMap] = await Promise.all([
            httpApiAsync("GET", "/v1/outbound"),
            httpApiAsync("GET", "/v1/policy_groups")
        ]);

        const modeRaw = outboundRes.mode || "rule";
        const isDirectMode = modeRaw === "direct";
        const hasProxyGroup = Boolean(groupsMap && groupsMap[POLICY_PROXY]);
        const proxyPolicy = hasProxyGroup ? POLICY_PROXY : "";

        const [directInfo, directV6, proxyInfo, proxyV6, directPing, proxyPing, routeText] = await Promise.all([
            fetchDirectInfo(),
            fetchIpv6Address(DIRECT_IPV6_PRIMARY_URL, DIRECT_IPV6_FALLBACK_URL, POLICY_DIRECT),
            fetchProxyInfo(proxyPolicy),
            fetchIpv6Address(PROXY_IPV6_PRIMARY_URL, PROXY_IPV6_FALLBACK_URL, proxyPolicy),
            httpGetTimed(DIRECT_PING_URL, POLICY_DIRECT),
            httpGetTimed(PROXY_PING_URL, proxyPolicy),
            hasProxyGroup ? resolvePolicyRoute(groupsMap, POLICY_PROXY) : Promise.resolve("")
        ]);

        const lines = buildPanelLines({
            localMeta,
            directInfo,
            directV6,
            proxyInfo,
            proxyV6,
            directPing,
            proxyPing,
            routeText
        });
        const style = pickPanelStyle(localMeta.isWifi, directInfo.ok, proxyInfo.ok, isDirectMode);
        $done({
            title: `${localMeta.netLabel} · ${modeRaw.toUpperCase()} (${formatTimeNow()})`,
            content: lines.join("\n"),
            icon: style.icon,
            "icon-color": style.color
        });
    } catch (err) {
        $done({
            title: "网络信息诊断异常",
            content: `脚本执行失败: ${String(err)}`,
            icon: "exclamationmark.triangle.fill",
            "icon-color": "#FF3B30"
        });
    }
}

main();
