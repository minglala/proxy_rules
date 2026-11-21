/**
 * Surge AI 与流媒体落地纯净度体检脚本
 * 按需触发：检测 AI/主代理出口 IP 属性与风险等级，并探测 ChatGPT、Gemini、Claude、Netflix、YouTube 真实解锁状态
 */

const POLICY_AI = "📟智能助理";
const POLICY_PROXY = "Proxy";
const POLICY_YOUTUBE = "▶️Youtube";

const IPAPI_IS_URL = "https://api.ipapi.is/";
const IP_API_FALLBACK_URL = "http://ip-api.com/json/?fields=status,countryCode,city,isp,org,as,hosting,proxy,query";

const CHATGPT_TRACE_URL = "https://chatgpt.com/cdn-cgi/trace";
const OPENAI_API_URL = "https://api.openai.com/v1/models";
const CLAUDE_TRACE_URL = "https://claude.ai/cdn-cgi/trace";
const ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages";
const GEMINI_WEB_URL = "https://gemini.google.com/";
const NETFLIX_NON_ORIGINAL_URL = "https://www.netflix.com/title/70143836";
const NETFLIX_ORIGINAL_URL = "https://www.netflix.com/title/80018499";
const YOUTUBE_PREMIUM_URL = "https://www.youtube.com/premium";

const REQUEST_TIMEOUT_SEC = 7;
const HTTP_OK = 200;
const HTTP_BAD_REQUEST = 400;
const HTTP_UNAUTHORIZED = 401;
const HTTP_FORBIDDEN = 403;
const HTTP_NOT_FOUND = 404;
const HTTP_METHOD_NOT_ALLOWED = 405;

const BROWSER_UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
const UNSUPPORTED_AI_REGIONS = new Set(["CN", "HK", "MO", "RU", "BY", "IR", "KP", "CU", "SY", "AF", "VE"]);

function httpApiAsync(method, path, body = {}) {
    return new Promise((resolve) => {
        $httpAPI(method, path, body, (res) => resolve(res || {}));
    });
}

function httpGetAsync(url, policy, extraHeaders = {}) {
    return new Promise((resolve) => {
        const opts = {
            url,
            timeout: REQUEST_TIMEOUT_SEC,
            headers: Object.assign({ "User-Agent": BROWSER_UA }, extraHeaders)
        };
        if (policy) {
            opts.policy = policy;
        }
        $httpClient.get(opts, (error, response, data) => {
            resolve({
                error: error || null,
                status: response ? response.status : 0,
                headers: (response && response.headers) ? response.headers : {},
                body: typeof data === "string" ? data : ""
            });
        });
    });
}

function parseTraceLocation(body) {
    const match = body.match(/^loc=([A-Z]{2})/m);
    return match ? match[1] : "";
}

function classifyIpApiIs(json) {
    const companyType = (json.company && json.company.type) || (json.asn && json.asn.type) || "";
    const isHosting = Boolean(json.is_datacenter) || companyType === "hosting";
    const isHighRisk = Boolean(json.is_abuser) || Boolean(json.is_tor);
    const isProxyFlag = Boolean(json.is_proxy) || Boolean(json.is_vpn);

    let typeLabel = "未知类型";
    if (isHosting) {
        typeLabel = "机房IP";
    } else if (companyType === "isp") {
        typeLabel = "住宅ISP";
    } else if (companyType === "business") {
        typeLabel = "商业宽带";
    } else if (companyType === "education") {
        typeLabel = "教育网";
    }

    let riskLabel = "低风险";
    let riskLevel = 0;
    if (isHighRisk || (isHosting && isProxyFlag)) {
        riskLabel = "高风险";
        riskLevel = 2;
    } else if (isHosting || isProxyFlag) {
        riskLabel = "中风险";
        riskLevel = 1;
    }

    return {
        ok: true,
        ip: json.ip || "-",
        country: (json.location && json.location.country_code) || "--",
        org: (json.asn && json.asn.org) || (json.company && json.company.name) || "",
        typeLabel,
        riskLabel,
        riskLevel
    };
}

function classifyIpApiFallback(json) {
    const isHosting = Boolean(json.hosting);
    const isProxyFlag = Boolean(json.proxy);
    const typeLabel = isHosting ? "机房IP" : "非机房";
    let riskLabel = "低风险";
    let riskLevel = 0;
    if (isHosting && isProxyFlag) {
        riskLabel = "高风险";
        riskLevel = 2;
    } else if (isHosting || isProxyFlag) {
        riskLabel = "中风险";
        riskLevel = 1;
    }
    return {
        ok: true,
        ip: json.query || "-",
        country: json.countryCode || "--",
        org: json.isp || json.org || "",
        typeLabel,
        riskLabel,
        riskLevel
    };
}

async function fetchIpPurity(policyName) {
    const primary = await httpGetAsync(IPAPI_IS_URL, policyName);
    if (!primary.error && primary.status === HTTP_OK && primary.body) {
        try {
            const json = JSON.parse(primary.body);
            if (json && json.ip) {
                return classifyIpApiIs(json);
            }
        } catch (_) {
            // 回退至备用接口
        }
    }

    const fallback = await httpGetAsync(IP_API_FALLBACK_URL, policyName);
    if (!fallback.error && fallback.status === HTTP_OK && fallback.body) {
        try {
            const json = JSON.parse(fallback.body);
            if (json && json.status === "success") {
                return classifyIpApiFallback(json);
            }
        } catch (_) {
            // 忽略解析异常
        }
    }
    return { ok: false, ip: "-", country: "--", org: "", typeLabel: "检测失败", riskLabel: "未知", riskLevel: 2 };
}

async function checkChatGPT(policyName) {
    const [traceRes, apiRes] = await Promise.all([
        httpGetAsync(CHATGPT_TRACE_URL, policyName),
        httpGetAsync(OPENAI_API_URL, policyName)
    ]);
    const loc = parseTraceLocation(traceRes.body);
    const locTag = loc ? `(${loc})` : "";

    if (loc && UNSUPPORTED_AI_REGIONS.has(loc)) {
        return { ok: false, text: `ChatGPT:受限${locTag}` };
    }
    if (apiRes.status === HTTP_UNAUTHORIZED) {
        return { ok: true, text: `ChatGPT:解锁${locTag}` };
    }
    if (apiRes.status === HTTP_FORBIDDEN) {
        const isGeo = apiRes.body.includes("unsupported_country");
        return { ok: false, text: isGeo ? `ChatGPT:受限${locTag}` : `ChatGPT:风控${locTag}` };
    }
    if (traceRes.status === HTTP_OK && loc) {
        return { ok: true, text: `ChatGPT:可用${locTag}` };
    }
    return { ok: false, text: "ChatGPT:超时" };
}

async function checkClaude(policyName) {
    const [traceRes, apiRes] = await Promise.all([
        httpGetAsync(CLAUDE_TRACE_URL, policyName),
        httpGetAsync(ANTHROPIC_API_URL, policyName)
    ]);
    const loc = parseTraceLocation(traceRes.body);
    const locTag = loc ? `(${loc})` : "";

    if (loc && UNSUPPORTED_AI_REGIONS.has(loc)) {
        return { ok: false, text: `Claude:受限${locTag}` };
    }
    const apiReachable = apiRes.status === HTTP_METHOD_NOT_ALLOWED
        || apiRes.status === HTTP_UNAUTHORIZED
        || apiRes.status === HTTP_BAD_REQUEST;
    if (apiReachable) {
        return { ok: true, text: `Claude:解锁${locTag}` };
    }
    if (apiRes.status === HTTP_FORBIDDEN) {
        return { ok: false, text: `Claude:风控${locTag}` };
    }
    return { ok: false, text: "Claude:超时" };
}

async function checkGemini(policyName, aiCountry) {
    const res = await httpGetAsync(GEMINI_WEB_URL, policyName, { "Accept-Language": "en-US,en;q=0.9" });
    const countryTag = (aiCountry && aiCountry !== "--") ? `(${aiCountry})` : "";

    if (aiCountry && UNSUPPORTED_AI_REGIONS.has(aiCountry)) {
        return { ok: false, text: `Gemini:受限${countryTag}` };
    }
    if (res.error || res.status === 0) {
        return { ok: false, text: "Gemini:超时" };
    }
    const blocked = res.body.includes("45631641,null,false")
        || res.body.includes("not available in your country");
    if (blocked) {
        return { ok: false, text: `Gemini:受限${countryTag}` };
    }
    if (res.status === HTTP_OK && (res.body.includes("45631641,null,true") || res.body.includes("WIZ_global_data"))) {
        return { ok: true, text: `Gemini:解锁${countryTag}` };
    }
    return { ok: false, text: `Gemini:异常(${res.status})` };
}

function parseNetflixRegion(headers) {
    const originUrl = headers["x-originating-url"] || headers["X-Originating-URL"] || "";
    const match = originUrl.match(/netflix\.com\/([a-z]{2})(?:-en)?\/title/i);
    return match ? match[1].toUpperCase() : "US";
}

async function checkNetflix(policyName) {
    const nonOrig = await httpGetAsync(NETFLIX_NON_ORIGINAL_URL, policyName);
    if (nonOrig.error || nonOrig.status === 0) {
        return { ok: false, text: "Netflix:超时" };
    }
    if (nonOrig.status === HTTP_OK) {
        const region = parseNetflixRegion(nonOrig.headers);
        return { ok: true, text: `Netflix:完整(${region})` };
    }
    if (nonOrig.status === HTTP_FORBIDDEN) {
        return { ok: false, text: "Netflix:屏蔽" };
    }
    if (nonOrig.status === HTTP_NOT_FOUND) {
        const orig = await httpGetAsync(NETFLIX_ORIGINAL_URL, policyName);
        if (orig.status === HTTP_OK) {
            return { ok: true, text: "Netflix:仅自制剧" };
        }
    }
    return { ok: false, text: `Netflix:受限(${nonOrig.status})` };
}

async function checkYouTube(policyName) {
    const res = await httpGetAsync(YOUTUBE_PREMIUM_URL, policyName, { "Accept-Language": "en-US,en;q=0.9" });
    if (res.error || res.status === 0) {
        return { ok: false, text: "YouTube:超时" };
    }
    const match = res.body.match(/"countryCode":"([A-Z]{2})"/) || res.body.match(/"INNERTUBE_CONTEXT_GL":"([A-Z]{2})"/);
    const region = match ? match[1] : "";
    const tag = region ? `(${region})` : "";
    if (res.body.includes("YouTube Premium is not available in your country")) {
        return { ok: false, text: `YouTube:受限${tag}` };
    }
    return { ok: true, text: `YouTube:解锁${tag}` };
}

function formatExitLine(label, profile) {
    if (!profile.ok) {
        return `${label}: 探测失败`;
    }
    return `${label}: ${profile.country} | ${profile.typeLabel} | ${profile.riskLabel} (${profile.ip})`;
}

function formatTimeNow() {
    const now = new Date();
    const hh = String(now.getHours()).padStart(2, "0");
    const mm = String(now.getMinutes()).padStart(2, "0");
    const ss = String(now.getSeconds()).padStart(2, "0");
    return `${hh}:${mm}:${ss}`;
}

function resolvePolicy(groupsMap, preferred, fallback) {
    if (groupsMap && groupsMap[preferred]) {
        return preferred;
    }
    if (fallback && groupsMap && groupsMap[fallback]) {
        return fallback;
    }
    return "";
}

function renderIdlePanel() {
    $done({
        title: "AI 与流媒体纯净度体检",
        content: "轻点右上角刷新执行深度体检\n检测项: AI/主代理出口风险画像 + ChatGPT / Gemini / Claude / Netflix / YouTube",
        icon: "waveform.path.ecg",
        "icon-color": "#007AFF"
    });
}

async function runFullAudit() {
    try {
        const groupsMap = await httpApiAsync("GET", "/v1/policy_groups");
        const aiPolicy = resolvePolicy(groupsMap, POLICY_AI, POLICY_PROXY);
        const proxyPolicy = resolvePolicy(groupsMap, POLICY_PROXY, "");
        const ytPolicy = resolvePolicy(groupsMap, POLICY_YOUTUBE, POLICY_PROXY);

        const [aiProfile, proxyProfile, chatgpt, claude, netflix, youtube] = await Promise.all([
            fetchIpPurity(aiPolicy),
            fetchIpPurity(proxyPolicy),
            checkChatGPT(aiPolicy),
            checkClaude(aiPolicy),
            checkNetflix(proxyPolicy),
            checkYouTube(ytPolicy)
        ]);
        const gemini = await checkGemini(aiPolicy, aiProfile.country);

        const lines = [];
        if (aiProfile.ok && proxyProfile.ok && aiProfile.ip === proxyProfile.ip) {
            lines.push(formatExitLine("共用出口", aiProfile));
        } else {
            lines.push(formatExitLine("AI出口", aiProfile));
            lines.push(formatExitLine("主出口", proxyProfile));
        }
        lines.push(`${chatgpt.text} | ${gemini.text}`);
        lines.push(`${claude.text}`);
        lines.push(`${netflix.text} | ${youtube.text}`);

        const aiAllOk = chatgpt.ok && gemini.ok && claude.ok;
        const streamAllOk = netflix.ok && youtube.ok;
        let icon = "checkmark.seal.fill";
        let color = "#34C759";
        if (!aiAllOk || aiProfile.riskLevel >= 2) {
            icon = "exclamationmark.triangle.fill";
            color = "#FF3B30";
        } else if (!streamAllOk || aiProfile.riskLevel === 1) {
            icon = "exclamationmark.shield.fill";
            color = "#FF9500";
        }

        $done({
            title: `纯净度体检 (${formatTimeNow()})`,
            content: lines.join("\n"),
            icon,
            "icon-color": color
        });
    } catch (err) {
        $done({
            title: "纯净度体检异常",
            content: `脚本执行失败: ${String(err)}`,
            icon: "xmark.octagon.fill",
            "icon-color": "#FF3B30"
        });
    }
}

if (typeof $trigger !== "undefined" && $trigger === "button") {
    runFullAudit();
} else {
    renderIdlePanel();
}
