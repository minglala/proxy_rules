/**
 * Surge 增强版网络信息诊断面板
 * 展示网络环境、内网/IPv6、国内直连与代理双出口公网 IP、IP 属性、当前策略链路及双通道延迟
 */

const POLICY_DIRECT = "DIRECT";
const POLICY_PROXY = "Proxy";

const DIRECT_IP_PRIMARY_URL = "https://myip.ipip.net/json";
const DIRECT_IP_FALLBACK_URL = "https://forge.speedtest.cn/api/location/info";
const PROXY_IP_PRIMARY_URL = "http://ip-api.com/json/?fields=status,countryCode,city,isp,org,hosting,proxy,query";
const PROXY_IP_FALLBACK_URL = "https://api.ip.sb/geoip";

const DIRECT_PING_URL = "http://connectivitycheck.platform.hicloud.com/generate_204";
const PROXY_PING_URL = "http://cp.cloudflare.com/generate_204";

const REQUEST_TIMEOUT_SEC = 5;
const HTTP_OK_MIN = 200;
const HTTP_OK_MAX = 300;
const MAX_POLICY_DEPTH = 3;
const LATENCY_INVALID = -1;

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
    const primary = await httpGetTimed(DIRECT_IP_PRIMARY_URL, POLICY_DIRECT);
    if (primary.ok) {
        const parsed = parseDirectIpip(primary.body);
        if (parsed) {
            return parsed;
        }
    }
    const fallback = await httpGetTimed(DIRECT_IP_FALLBACK_URL, POLICY_DIRECT);
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
    const primary = await httpGetTimed(PROXY_IP_PRIMARY_URL, proxyPolicy);
    if (primary.ok) {
        const parsed = parseProxyIpApi(primary.body);
        if (parsed) {
            return parsed;
        }
    }
    const fallback = await httpGetTimed(PROXY_IP_FALLBACK_URL, proxyPolicy);
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

const IPV6_LINK_LOCAL_PREFIX = "fe80:";
const IPV6_ULA_PREFIX_FC = "fc";
const IPV6_ULA_PREFIX_FD = "fd";

function classifyIpv6Status(v6Address) {
    if (!v6Address || typeof v6Address !== "string") {
        return "仅IPv4";
    }
    const lower = v6Address.toLowerCase();
    if (lower.startsWith(IPV6_LINK_LOCAL_PREFIX)) {
        return "仅IPv4";
    }
    if (lower.startsWith(IPV6_ULA_PREFIX_FC) || lower.startsWith(IPV6_ULA_PREFIX_FD)) {
        return "内网IPv6";
    }
    return "双栈";
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
    const stackTag = classifyIpv6Status(v6.primaryAddress);

    const lanLine = isWifi && routerText
        ? `内网: ${ipText} / ${routerText} (${stackTag})`
        : `本机: ${ipText}${v4.primaryInterface ? ` (${v4.primaryInterface})` : ""} (${stackTag})`;

    return { isWifi, netLabel, lanLine };
}

function formatPing(ms) {
    return ms > 0 ? `${ms}ms` : "超时";
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

async function main() {
    try {
        const localMeta = getLocalNetworkMeta();
        const [outboundRes, groupsMap] = await Promise.all([
            httpApiAsync("GET", "/v1/outbound"),
            httpApiAsync("GET", "/v1/policy_groups")
        ]);

        const modeRaw = outboundRes.mode || "rule";
        const modeUpper = modeRaw.toUpperCase();
        const isDirectMode = modeRaw === "direct";
        const hasProxyGroup = Boolean(groupsMap && groupsMap[POLICY_PROXY]);
        const proxyPolicy = hasProxyGroup ? POLICY_PROXY : "";

        const [directInfo, proxyInfo, directPing, proxyPing, routeText] = await Promise.all([
            fetchDirectInfo(),
            fetchProxyInfo(proxyPolicy),
            httpGetTimed(DIRECT_PING_URL, POLICY_DIRECT),
            httpGetTimed(PROXY_PING_URL, proxyPolicy),
            hasProxyGroup ? resolvePolicyRoute(groupsMap, POLICY_PROXY) : Promise.resolve("")
        ]);

        const directLine = directInfo.ok
            ? `直连: ${directInfo.ip}${directInfo.detail ? ` (${directInfo.detail})` : ""}`
            : "直连: 探测失败";

        const proxyTags = [proxyInfo.region, proxyInfo.typeTag].filter(Boolean).join(" · ");
        const proxyLine = proxyInfo.ok
            ? `节点: ${proxyInfo.ip}${proxyTags ? ` (${proxyTags})` : ""}`
            : "节点: 探测失败";

        const ispParts = [];
        if (proxyInfo.ok && proxyInfo.isp) {
            ispParts.push(`落地: ${proxyInfo.isp}`);
        }
        if (routeText) {
            ispParts.push(`策略: ${routeText}`);
        }

        const latencyLine = `延迟: 国内 ${formatPing(directPing.ms)} | 代理 ${formatPing(proxyPing.ms)}`;
        const lines = [localMeta.lanLine, directLine, proxyLine];
        if (ispParts.length > 0) {
            lines.push(ispParts.join(" | "));
        }
        lines.push(latencyLine);

        const style = pickPanelStyle(localMeta.isWifi, directInfo.ok, proxyInfo.ok, isDirectMode);
        $done({
            title: `${localMeta.netLabel} · ${modeUpper}`,
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
