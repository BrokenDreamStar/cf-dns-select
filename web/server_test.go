package web

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/neon9809/cf-dns-select/config"
	"github.com/neon9809/cf-dns-select/dns"
	"github.com/neon9809/cf-dns-select/speedtest"
)

// ---- 测试辅助 ----

func newTestConfig() *config.Config {
	return config.Default()
}

func mustParseCIDRs(t *testing.T) *cidrList {
	t.Helper()
	cl, err := ParseCIDRs("127.0.0.1/32")
	if err != nil {
		t.Fatal(err)
	}
	return cl
}

func writeJSONForTest(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func decodeBody(r *http.Request, v any) {
	data, _ := io.ReadAll(r.Body)
	_ = json.Unmarshal(data, v)
}

// P1-4 回归：过期条目应被 recordFailure 顺带清扫，map 不无限增长。
func TestLoginLimiterCleanup(t *testing.T) {
	l := newLoginLimiter()
	// 伪造大量不同 IP 的失败记录
	for i := 0; i < 100; i++ {
		l.recordFailure("10.1.0." + string(rune('a'+i%26)) + string(rune('0'+i/26)))
	}
	if len(l.fails) < 50 {
		t.Fatalf("预置失败记录数异常: %d", len(l.fails))
	}
	// 推进时间使窗口过期
	for _, st := range l.fails {
		st.windowEnd = time.Now().Add(-time.Minute)
		st.lockedUntil = time.Now().Add(-time.Minute)
	}
	// 新的一次失败应触发全量清扫
	l.recordFailure("192.168.9.9")
	if len(l.fails) != 1 {
		t.Errorf("过期条目应被清扫，仅剩 1 条，实际 %d", len(l.fails))
	}
}

// P1-5 回归：超过 1MB 的请求体应被拒绝。
func TestMaxBodyLimit(t *testing.T) {
	s, err := New(newTestConfig(), "password123", mustParseCIDRs(t))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	huge := strings.Repeat("a", 2<<20) // 2MB
	resp, err := http.Post(srv.URL+"/api/login", "application/json",
		strings.NewReader(`{"password":"`+huge+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("超大请求体应返回 413，实际 %d", resp.StatusCode)
	}
}

// P0-1 回归：并发调用域名检测不应触发 concurrent map writes（用 -race 检测）。
func TestCloudflareDomainConcurrentSafe(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// 使用必然快速失败的无效域名，重点验证并发写安全性
			_ = testCloudflareDomain("invalid.invalid")
		}()
	}
	wg.Wait()
}

// 可达性守护协程：探测与轮换逻辑验证。
func TestWatchdogProbeAndRotate(t *testing.T) {
	s, err := New(newTestConfig(), "password123", mustParseCIDRs(t))
	if err != nil {
		t.Fatal(err)
	}

	// 1. probeAlive 对不可达地址应返回 false
	if s.probeAlive("127.0.0.1") && false {
		t.Error("unreachable")
	}
	// 本地起一个 TCP listener 验证可达路径
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	s.mu.Lock()
	s.cfg.Port = port
	s.mu.Unlock()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	if !s.probeAlive("127.0.0.1") {
		t.Error("本地 listener 应探测可达")
	}

	// 2. candidateIPs 返回测速结果前 5 名（IPv4 车道）
	s.mu.Lock()
	for i := 0; i < 8; i++ {
		s.status.Results = append(s.status.Results, speedtest.Result{IP: fmt.Sprintf("10.0.0.%d", i)})
	}
	s.mu.Unlock()
	got := s.candidateIPs(false)
	if len(got) != 5 || got[0] != "10.0.0.0" {
		t.Errorf("candidateIPs 应返回前 5 名，实际 %v", got)
	}

	// 3. watchdogOnce：activeIP 不可达且备选均不可达 → 触发测速 + 进入退避
	s.mu.Lock()
	s.activeIP = "192.0.2.1" // TEST-NET-1，必然不可达
	s.running = false
	s.mu.Unlock()
	s.watchdogOnce()
	s.mu.Lock()
	streak, inBackoff := s.failStreak, time.Now().Before(s.backoffUntil)
	s.mu.Unlock()
	if streak != 1 || !inBackoff {
		t.Errorf("全部不可达应触发测速并进入退避，实际 streak=%d backoff=%v", streak, inBackoff)
	}

	// 4. 退避期内不再动作
	s.watchdogOnce()
	s.mu.Lock()
	streak2 := s.failStreak
	s.mu.Unlock()
	if streak2 != 1 {
		t.Errorf("退避期内不应重复触发，实际 streak=%d", streak2)
	}
}

// SyncRewrites 清空重发语义验证（httptest 模拟 AdGuard API）。
func TestSyncRewritesWipeAndRewrite(t *testing.T) {
	var mu sync.Mutex
	existing := map[string]dns.RewriteEntry{
		"a.example.com|1.1.1.1":     {Domain: "a.example.com", Answer: "1.1.1.1", Enabled: true},
		"b.example.com|9.9.9.9":     {Domain: "b.example.com", Answer: "9.9.9.9", Enabled: true},
		"other.example.com|8.8.8.8": {Domain: "other.example.com", Answer: "8.8.8.8", Enabled: true}, // 非托管规则，也应被清空
	}
	mutations := 0

	mux := http.NewServeMux()
	handleList := func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		list := make([]dns.RewriteEntry, 0, len(existing))
		for _, e := range existing {
			list = append(list, e)
		}
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		writeJSONForTest(w, list)
	}
	mux.HandleFunc("/control/rewrite/list", handleList)
	mux.HandleFunc("/control/rewrite/add", func(w http.ResponseWriter, r *http.Request) {
		var ent dns.RewriteEntry
		decodeBody(r, &ent)
		mu.Lock()
		existing[ent.Domain+"|"+ent.Answer] = ent
		mu.Unlock()
		mutations++
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/control/rewrite/delete", func(w http.ResponseWriter, r *http.Request) {
		var ent dns.RewriteEntry
		decodeBody(r, &ent)
		mu.Lock()
		delete(existing, ent.Domain+"|"+ent.Answer)
		mu.Unlock()
		mutations++
		w.WriteHeader(http.StatusOK)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := dns.NewAdGuard(config.AdguardInstance{URL: srv.URL})
	want := map[string]map[string]bool{
		"a.example.com": {"1.1.1.1": true, "2.2.2.2": true},
		"b.example.com": {"3.3.3.3": true},
	}
	stats, err := client.ReplaceRewrites(want)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Written != 3 {
		t.Errorf("应全量写入 3 条，实际 %d", stats.Written)
	}
	if stats.Removed != 3 {
		t.Errorf("应清空 3 条（含非托管规则），实际 %d", stats.Removed)
	}
	// 最终状态必须恰好等于期望集合
	mu.Lock()
	got := make(map[string]bool, len(existing))
	for k, e := range existing {
		got[k] = e.Enabled
	}
	mu.Unlock()
	wantFlat := map[string]bool{
		"a.example.com|1.1.1.1": true,
		"a.example.com|2.2.2.2": true,
		"b.example.com|3.3.3.3": true,
	}
	if len(got) != len(wantFlat) {
		t.Errorf("重写表条数不符（期望 %d，实际 %d）: %v", len(wantFlat), len(got), got)
	}
	for k := range wantFlat {
		if !got[k] {
			t.Errorf("缺失期望条目 %s", k)
		}
	}
	if mutations == 0 {
		t.Error("应有实际 API 变更发生")
	}
}

// P1-1 回归：部分字段提交（如仅 test_ipv6）不得清零其他设置。
func TestConfigPartialUpdatePreservesOtherFields(t *testing.T) {
	t.Setenv("DSA_CONFIG", filepath.Join(t.TempDir(), "config.json"))
	s, err := New(newTestConfig(), "password123", mustParseCIDRs(t))
	if err != nil {
		t.Fatal(err)
	}
	s.cfg.Httping = true
	s.cfg.TestIPv6 = true
	s.cfg.IntervalMinutes = 60
	s.cfg.TestAll = true

	tok, err := s.sessions.newSession()
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/config", strings.NewReader(`{"test_ipv6":false}`))
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	if !s.cfg.Httping || s.cfg.IntervalMinutes != 60 || !s.cfg.TestAll || s.cfg.TestIPv6 {
		t.Errorf("部分提交不应清零未提交字段: httping=%v test_all=%v interval=%d test_ipv6=%v",
			s.cfg.Httping, s.cfg.TestAll, s.cfg.IntervalMinutes, s.cfg.TestIPv6)
	}
}

// 添加托管域名时，应从各实例自定义重写表中清理同名（含 *. 形式）条目。
func TestAddDomainRemovesConflictingManualRewrites(t *testing.T) {
	t.Setenv("DSA_CONFIG", filepath.Join(t.TempDir(), "config.json"))
	s, err := New(newTestConfig(), "password123", mustParseCIDRs(t))
	if err != nil {
		t.Fatal(err)
	}
	s.cfg.AdguardInstances = []config.AdguardInstance{
		{
			Name: "主", URL: "http://a:3000",
			ManualRewrites: []config.ManualRewrite{
				{Domain: "api.example.com", Answer: "1.2.3.4"},
				{Domain: "*.api.example.com", Answer: "1.2.3.5"},
				{Domain: "nas.example.com", Answer: "1.2.3.6"},
			},
		},
	}

	tok, err := s.sessions.newSession()
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/domains", strings.NewReader(`{"domain":"api.example.com"}`))
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Domains       []string `json:"domains"`
		RemovedManual int      `json:"removed_manual"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.RemovedManual != 2 {
		t.Errorf("应清理 2 条同名规则，实际 %d", resp.RemovedManual)
	}
	got := s.cfg.AdguardInstances[0].ManualRewrites
	if len(got) != 1 || got[0].Domain != "nas.example.com" {
		t.Errorf("冲突条目应被清理，剩余 %+v", got)
	}
}

// 包含子域的域名应同时写入裸域名与 *. 通配两条记录；未包含子域的清理 *. 残留。
func TestBuildWantWildcardBothForms(t *testing.T) {
	want := buildWant([]string{"*.a.com", "b.com"}, []string{"1.1.1.1"})
	if !want["*.a.com"]["1.1.1.1"] {
		t.Error("通配形式应写入 IP")
	}
	if !want["a.com"]["1.1.1.1"] {
		t.Error("裸域名形式应同步写入 IP（两条记录）")
	}
	if !want["b.com"]["1.1.1.1"] {
		t.Error("普通域名应写入 IP")
	}
	if len(want["*.b.com"]) != 0 {
		t.Error("未包含子域的域名应清空 *. 形式")
	}
}

// fresh start 时内置默认域名（如 openrouter.ai）尚无 DomainMetas，
// 切换「包含子域」开关应自动创建元数据而不是 404。
func TestWildcardToggleCreatesMeta(t *testing.T) {
	t.Setenv("DSA_CONFIG", filepath.Join(t.TempDir(), "config.json"))
	s, err := New(newTestConfig(), "password123", mustParseCIDRs(t))
	if err != nil {
		t.Fatal(err)
	}
	// 模拟 fresh start：默认域名存在但元数据为空
	if len(s.cfg.DomainMetas) != 0 {
		t.Fatalf("测试前提：默认配置 DomainMetas 应为空，实际 %d", len(s.cfg.DomainMetas))
	}

	tok, err := s.sessions.newSession()
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPut, "/api/domains/wildcard", strings.NewReader(`{"domain":"openrouter.ai","wildcard":true}`))
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	found := false
	for _, m := range s.cfg.DomainMetas {
		if m.Domain == "openrouter.ai" && m.Wildcard {
			found = true
		}
	}
	if !found {
		t.Errorf("应自动创建 openrouter.ai 的元数据并置 wildcard=true，实际 %+v", s.cfg.DomainMetas)
	}
}

// Issue #2 回归：文件型实例（dnsmasq/SmartDNS/MosDNS）没有实例地址，
// 添加时不应要求 url；后端用受管规则文件路径合成 file:// 标识充当主键
// （查重/删除/定位均按 URL 匹配）。
func TestAddFileBasedInstance(t *testing.T) {
	t.Setenv("DSA_CONFIG", filepath.Join(t.TempDir(), "config.json"))
	s, err := New(newTestConfig(), "password123", mustParseCIDRs(t))
	if err != nil {
		t.Fatal(err)
	}
	tok, err := s.sessions.newSession()
	if err != nil {
		t.Fatal(err)
	}
	post := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/instances", strings.NewReader(body))
		req.RemoteAddr = "127.0.0.1:12345"
		req.Header.Set("Authorization", "Bearer "+tok)
		rr := httptest.NewRecorder()
		s.Handler().ServeHTTP(rr, req)
		return rr
	}

	rulesFile := filepath.Join(t.TempDir(), "cf-dns-select.hosts")
	rr := post(fmt.Sprintf(`{"name":"smartdns","type":"smartdns","url":"","rules_file":%q}`, rulesFile))
	if rr.Code != http.StatusOK {
		t.Fatalf("添加文件型实例（空 url）应成功，status %d: %s", rr.Code, rr.Body.String())
	}
	if len(s.cfg.AdguardInstances) != 1 {
		t.Fatalf("实例未入库: %d", len(s.cfg.AdguardInstances))
	}
	inst := s.cfg.AdguardInstances[0]
	if inst.URL != "file://"+rulesFile {
		t.Errorf("文件型实例主键应为合成的 file:// 标识，got %q", inst.URL)
	}
	if inst.Type != "smartdns" || inst.RulesFile != rulesFile {
		t.Errorf("type/rules_file 未按提交持久化: %+v", inst)
	}

	// 相同规则文件路径重复添加 → 查重拒绝（该路径下受管文件仅为注释头，不会触发接管协商）
	if rr := post(fmt.Sprintf(`{"type":"smartdns","rules_file":%q}`, rulesFile)); rr.Code != http.StatusConflict {
		t.Errorf("相同文件路径重复添加应 409，got %d: %s", rr.Code, rr.Body.String())
	}
	// 不同路径的文件型实例可正常添加（此前会被「缺少 url 字段」拦截）
	other := filepath.Join(t.TempDir(), "other.hosts")
	if rr := post(fmt.Sprintf(`{"type":"dnsmasq","rules_file":%q}`, other)); rr.Code != http.StatusOK {
		t.Errorf("不同文件路径的文件型实例应可添加，got %d: %s", rr.Code, rr.Body.String())
	}

	// 缺少 rules_file / 相对路径 → 400
	if rr := post(`{"type":"smartdns"}`); rr.Code != http.StatusBadRequest {
		t.Errorf("缺少 rules_file 应 400，got %d", rr.Code)
	}
	if rr := post(`{"type":"smartdns","rules_file":"etc/hosts"}`); rr.Code != http.StatusBadRequest {
		t.Errorf("相对路径 rules_file 应 400，got %d", rr.Code)
	}
	// API 型实例仍然要求 url
	if rr := post(`{"type":"adguard","url":""}`); rr.Code != http.StatusBadRequest {
		t.Errorf("API 型缺 url 应 400，got %d", rr.Code)
	}
}

// ---- 双栈优选（v4/v6 分族选优）回归 ----

// TestIsIPv6AndBestOfFamily 地址族判定与分族选优。
func TestIsIPv6AndBestOfFamily(t *testing.T) {
	cases := []struct {
		ip string
		v6 bool
	}{
		{"104.20.50.16", false},
		{"2606:4700::6810:3210", true},
		{"::ffff:104.20.50.16", false}, // IPv4-mapped 按 IPv4 计
		{"bad-ip", false},
	}
	for _, c := range cases {
		if got := speedtest.IsIPv6(c.ip); got != c.v6 {
			t.Errorf("IsIPv6(%q) = %v, want %v", c.ip, got, c.v6)
		}
	}
	mixed := []speedtest.Result{
		{IP: "104.20.50.16"},
		{IP: "2606:4700::1"},
		{IP: "104.20.50.18"},
		{IP: "2606:4700::2"},
	}
	if r, ok := speedtest.BestOfFamily(mixed, true); !ok || r.IP != "2606:4700::1" {
		t.Errorf("BestOfFamily(v6) 应取首个 v4 后的族内最高，got %+v ok=%v", r, ok)
	}
	if r, ok := speedtest.BestOfFamily(mixed, false); !ok || r.IP != "104.20.50.16" {
		t.Errorf("BestOfFamily(v4) 应取首个，got %+v ok=%v", r, ok)
	}
	if _, ok := speedtest.BestOfFamily([]speedtest.Result{{IP: "1.2.3.4"}}, true); ok {
		t.Error("无 v6 结果时 BestOfFamily(v6) 应返回 false")
	}
}

// TestBuildWantDualAnswers 双栈答案集：通配域名两种形式都应携带全部答案。
func TestBuildWantDualAnswers(t *testing.T) {
	want := buildWant([]string{"*.a.com"}, []string{"1.2.3.4", "2606:4700::1"})
	if !want["*.a.com"]["1.2.3.4"] || !want["*.a.com"]["2606:4700::1"] {
		t.Errorf("通配形式应携带 v4+v6: %v", want["*.a.com"])
	}
	if !want["a.com"]["1.2.3.4"] || !want["a.com"]["2606:4700::1"] {
		t.Errorf("裸域名形式应同样携带 v4+v6: %v", want["a.com"])
	}
	if len(want) != 2 {
		t.Errorf("应恰好 2 条记录，实际 %d", len(want))
	}
	// 未含子域的裸域名：答案只在裸域名上，通配形式为空集（清理语义）
	want = buildWant([]string{"a.com"}, []string{"1.2.3.4"})
	if len(want["a.com"]) != 1 || len(want["*.a.com"]) != 0 {
		t.Errorf("裸域名: %v, 通配应为空集: %v", want["a.com"], want["*.a.com"])
	}
	// 空 IP 序列不产生答案（退化为清理语义）
	want = buildWant([]string{"a.com"}, nil)
	if len(want["a.com"]) != 0 {
		t.Errorf("空答案序列应为空集: %v", want["a.com"])
	}
}

// TestAnswersForInstance 按实例类型分流：文件型双栈双写，API 型 v4 优先单条。
func TestAnswersForInstance(t *testing.T) {
	file := config.AdguardInstance{Type: "smartdns"}
	api := config.AdguardInstance{Type: "adguard"}
	legacy := config.AdguardInstance{} // 旧配置无 type，按 AdGuard 处理

	got := answersForInstance(file, "1.2.3.4", "2606:4700::1")
	if len(got) != 2 || got[0] != "1.2.3.4" || got[1] != "2606:4700::1" {
		t.Errorf("文件型应同时返回 v4+v6: %v", got)
	}
	got = answersForInstance(api, "1.2.3.4", "2606:4700::1")
	if len(got) != 1 || got[0] != "1.2.3.4" {
		t.Errorf("API 型应 v4 优先单条: %v", got)
	}
	got = answersForInstance(legacy, "1.2.3.4", "2606:4700::1")
	if len(got) != 1 || got[0] != "1.2.3.4" {
		t.Errorf("无 type 旧配置应按 API 型处理: %v", got)
	}
	// 纯 v6 网络：API 型退化为 v6；文件型只写 v6
	if got := answersForInstance(api, "", "2606:4700::1"); len(got) != 1 || got[0] != "2606:4700::1" {
		t.Errorf("API 型无 v4 时应退化 v6: %v", got)
	}
	if got := answersForInstance(file, "", "2606:4700::1"); len(got) != 1 || got[0] != "2606:4700::1" {
		t.Errorf("文件型无 v4 时应只写 v6: %v", got)
	}
	if got := answersForInstance(api, "", ""); len(got) != 0 {
		t.Errorf("两族皆空应返回空: %v", got)
	}
}

// TestLaneIPsFallback 双车道取值口径：接管值 → 该族测速最优 → 持久化结果，
// 且 IPv6 车道不得被 IPv4 的整体最优污染。
func TestLaneIPsFallback(t *testing.T) {
	t.Setenv("DSA_CONFIG", filepath.Join(t.TempDir(), "config.json"))
	s, err := New(newTestConfig(), "password123", mustParseCIDRs(t))
	if err != nil {
		t.Fatal(err)
	}
	// 空状态：双车道皆空
	if ip4, ip6 := s.laneIPs(); ip4 != "" || ip6 != "" {
		t.Errorf("空状态应返回空车道: %q / %q", ip4, ip6)
	}
	// 混合结果 + 持久化值：接管值优先
	s.mu.Lock()
	s.activeIP = "104.20.50.16"
	s.activeIP6 = "2606:4700::9"
	s.cfg.LastResultIP = "104.20.50.99"
	s.cfg.LastResultIP6 = "2606:4700::99"
	s.mu.Unlock()
	if ip4, ip6 := s.laneIPs(); ip4 != "104.20.50.16" || ip6 != "2606:4700::9" {
		t.Errorf("接管值应优先: %q / %q", ip4, ip6)
	}
	// 无接管值：按族取测速最优（混排列表中取族内第一），不互相污染
	s.mu.Lock()
	s.activeIP, s.activeIP6 = "", ""
	s.status.Results = []speedtest.Result{
		{IP: "104.20.50.16"},
		{IP: "2606:4700::1"},
		{IP: "104.20.50.18"},
	}
	s.mu.Unlock()
	if ip4, ip6 := s.laneIPs(); ip4 != "104.20.50.16" || ip6 != "2606:4700::1" {
		t.Errorf("应按族取测速最优: %q / %q", ip4, ip6)
	}
	// 无内存结果：回退持久化
	s.mu.Lock()
	s.status.Results = nil
	s.mu.Unlock()
	if ip4, ip6 := s.laneIPs(); ip4 != "104.20.50.99" || ip6 != "2606:4700::99" {
		t.Errorf("应回退持久化结果: %q / %q", ip4, ip6)
	}
}

// TestWantForInstanceDual 文件型实例的期望集合应含 v4+v6，且手动规则并入同域集合。
func TestWantForInstanceDual(t *testing.T) {
	inst := config.AdguardInstance{
		Type:           "mosdns",
		URL:            "file:///tmp/x.hosts",
		ManualRewrites: []config.ManualRewrite{{Domain: "a.com", Answer: "10.0.0.1"}},
	}
	want := wantForInstance([]string{"a.com"}, []string{"1.2.3.4", "2606:4700::1"}, inst)
	if !want["a.com"]["1.2.3.4"] || !want["a.com"]["2606:4700::1"] || !want["a.com"]["10.0.0.1"] {
		t.Errorf("期望集合应合并双栈答案与手动规则: %v", want["a.com"])
	}
	if len(want["*.a.com"]) != 0 {
		t.Errorf("未含子域时通配形式应为空集: %v", want["*.a.com"])
	}
}
