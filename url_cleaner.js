/**
 * Surge URL 追踪参数净化脚本
 * 触发类型: http-request
 */

const TRACKING_PARAM_PREFIXES = ["utm_", "spm_"];
const TRACKING_PARAMS = new Set([
    "spm",
    "vd_source",
    "share_source",
    "share_medium",
    "share_token",
    "share_plat",
    "share_session_id",
    "share_from",
    "share_tag",
    "bbid",
    "ts",
    "source",
    "from",
    "isappinstalled",
    "fbclid",
    "gclid",
    "yclid",
    "mc_cid",
    "mc_eid",
    "igshid",
    "igsh",
    "si",
    "ref",
    "ref_src",
    "ref_url",
    "mkt_tok"
]);

function isTrackingKey(rawKey) {
    let key = rawKey;
    try {
        key = decodeURIComponent(rawKey);
    } catch (_) {
        // 保留原始键名做匹配
    }
    const normalized = key.trim().toLowerCase();
    if (!normalized) {
        return false;
    }
    if (TRACKING_PARAMS.has(normalized)) {
        return true;
    }
    return TRACKING_PARAM_PREFIXES.some((prefix) => normalized.startsWith(prefix));
}

function cleanTrackingUrl(rawUrl) {
    const hashIndex = rawUrl.indexOf("#");
    const hashPart = hashIndex !== -1 ? rawUrl.substring(hashIndex) : "";
    const urlWithoutHash = hashIndex !== -1 ? rawUrl.substring(0, hashIndex) : rawUrl;

    const queryIndex = urlWithoutHash.indexOf("?");
    if (queryIndex === -1) {
        return rawUrl;
    }

    const basePart = urlWithoutHash.substring(0, queryIndex);
    const queryPart = urlWithoutHash.substring(queryIndex + 1);
    const keptParams = queryPart.split("&").filter((pair) => {
        if (!pair) {
            return false;
        }
        const eqIndex = pair.indexOf("=");
        const rawKey = eqIndex !== -1 ? pair.substring(0, eqIndex) : pair;
        return !isTrackingKey(rawKey);
    });

    const rebuiltQuery = keptParams.length > 0 ? `?${keptParams.join("&")}` : "";
    return `${basePart}${rebuiltQuery}${hashPart}`;
}

const originalUrl = ($request && $request.url) ? $request.url : "";
const cleanedUrl = originalUrl ? cleanTrackingUrl(originalUrl) : "";

if (cleanedUrl && cleanedUrl !== originalUrl) {
    $done({ url: cleanedUrl });
} else {
    $done({});
}
