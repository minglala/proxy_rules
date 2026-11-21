/**
 * Surge 网络环境切换自动刷新 DNS 缓存
 * 触发事件: network-changed
 */
$httpAPI("POST", "/v1/dns/flush", {}, (res) => {
    console.log("DNS cache flushed on network change.");
    $done();
});
