// Package web 提供 dashboard 的 HTTP API 与内嵌 Web UI。
package web

import (
	"crypto/tls"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/neon9809/cf-dns-select/config"
	"github.com/neon9809/cf-dns-select/dns"
	"github.com/neon9809/cf-dns-select/speedtest"
)

//go:embed static
var staticFS embed.FS

// version 由构建时 -ldflags 注入（main.SetVersion 同步），或经 SetVersion 设置。
var version = "dev"

// SetVersion 供 main 在启动时同步版本号（ldflags 只注入 main.version）。
func SetVersion(v string) { version = v }

// Status 是 dashboard 首页展示的运行状态。
type Status struct {
	Running        bool                `json:"running"`
	Progress       *speedtest.Progress `json:"progress,omitempty"` // 测速进行中的实时进度（含正在测试的地址）
	LastRunTime    string              `json:"last_run_time"`
	LastError      string              `json:"last_error,omitempty"`
	BestIP         string              `json:"best_ip,omitempty"`
	BestDelayMs    float64             `json:"best_delay_ms,omitempty"`
	BestSpeedMBps  float64             `json:"best_speed_mbps,omitempty"`
	BestColo       string              `json:"best_colo,omitempty"`
	Results        []speedtest.Result  `json:"results,omitempty"`
	WrittenDomains []WrittenDomain     `json:"written_domains,omitempty"`
}

// RunRecord 记录一次测速任务的摘要（用于 Status 页的任务历史列表）。
type RunRecord struct {
	Time      string             `json:"time"`    // 开始时间
	Trigger   string             `json:"trigger"` // 触发方式：manual / schedule / startup
	OK        bool               `json:"ok"`
	Error     string             `json:"error,omitempty"`
	BestIP    string             `json:"best_ip,omitempty"`
	DelayMs   float64            `json:"delay_ms,omitempty"`
	SpeedMBps float64            `json:"speed_mbps,omitempty"`
	Colo      string             `json:"colo,omitempty"`
	Written   int                `json:"written"`           // 写入的重写条数
	DurationS float64            `json:"duration_s"`        // 耗时（秒）
	Results   []speedtest.Result `json:"results,omitempty"` // 该次任务的 Top 结果（弹窗展示用）
}

// maxRunHistory 任务历史保留条数。
const maxRunHistory = 10

// WrittenDomain 记录一次测速后写入了哪些实例/域名的重写规则。
type WrittenDomain struct {
	Instance string `json:"instance"` // AdGuard 实例名
	Domain   string `json:"domain"`
	Answer   string `json:"answer"`
	Time     string `json:"time"`
	Error    string `json:"error,omitempty"`
}

// Server 是 dashboard 服务。
type Server struct {
	cfg *config.Config

	password     string        // Dashboard 登录密码（首次启动随机生成并打印到日志）
	allowedCIDRs *cidrList     // 允许访问的来源网段（必须显式配置）
	sessions     *sessionStore // 会话存储
	loginLimit   *loginLimiter // 登录防爆破（按来源 IP 失败锁定）

	mu        sync.Mutex // 保护 cfg / status / running / scheduler
	status    Status
	history   []RunRecord // 最近测速任务历史（新在前，最多 maxRunHistory 条）
	running   bool
	runners   sync.WaitGroup // P0-2：跟踪在途测速任务，供优雅关闭等待
	syncState syncJob        // P1-7：实例同步异步任务状态

	// 可达性守护协程状态（单 IP 写入策略下的故障轮换）
	activeIP      string        // 当前写入实例的生效 IP（可能已从最优轮换到备选）
	failStreak    int           // 连续触发测速但无可用结果的次数（指数退避依据）
	backoffUntil  time.Time     // 退避截止时间：在此之前不再重复触发测速
	watchdogStop  chan struct{} // 可达性守护协程停止信号
	stopChan      chan struct{}
	ticker        *time.Ticker
	schedInterval int // 当前生效的测速间隔（分钟），用于跳过无变化的调度器重启
}

// maxStatusResults 状态接口保留的测速结果条数上限（防止 test_all 大结果集撑爆内存/带宽）。
const maxStatusResults = 100

// New 创建 dashboard 服务。
// password 为空时自动生成随机密码（调用方负责打印到日志）；
// cidrs 为必须显式配置的来源白名单。
func New(cfg *config.Config, password string, cidrs *cidrList) (*Server, error) {
	if password == "" {
		return nil, fmt.Errorf("Dashboard 登录密码不能为空")
	}
	s := &Server{
		cfg:          cfg,
		password:     password,
		allowedCIDRs: cidrs,
		sessions:     newSessionStore(),
		loginLimit:   newLoginLimiter(),
	}
	// TLS 反代场景：设置 DSA_SECURE_COOKIES=1 使会话 cookie 携带 Secure 标志
	if os.Getenv("DSA_SECURE_COOKIES") == "1" || strings.EqualFold(os.Getenv("DSA_SECURE_COOKIES"), "true") {
		secureCookies = true
	}
	s.status.Results = []speedtest.Result{}
	s.status.WrittenDomains = []WrittenDomain{}
	return s, nil
}

// maxRequestBody 单个请求体大小上限（1MB，足够容纳配置/域名/实例等 JSON 提交）。
const maxRequestBody = 1 << 20

// limitBody 限制请求体大小（P1-5）：防止超大 body 打爆内存。
// 超限时后续 Decode 会报错，Go 自动返回 413。
func limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
		next.ServeHTTP(w, r)
	})
}

// Handler 返回全部路由。
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// 公开路由：登录、健康检查、静态资源（均受请求体大小限制）
	mux.Handle("/api/login", limitBody(http.HandlerFunc(s.handleLogin)))
	mux.Handle("/api/logout", limitBody(http.HandlerFunc(s.handleLogout)))
	mux.HandleFunc("/api/health", s.handleHealth)
	sub, _ := fs.Sub(staticFS, "static")
	mux.Handle("/", http.FileServer(http.FS(sub)))

	// 鉴权路由：全部 API
	mux.Handle("/api/status", limitBody(s.authMiddleware(s.handleStatus)))
	mux.Handle("/api/config", limitBody(s.authMiddleware(s.handleConfig)))
	mux.Handle("/api/run", limitBody(s.authMiddleware(s.handleRun)))
	mux.Handle("/api/domains", limitBody(s.authMiddleware(s.handleDomains)))
	// 前缀路由：DELETE /api/domains/{name} 路径参数形式。
	// Go ServeMux 的 "/api/domains" 是精确匹配，不含子路径，
	// 不注册这条则所有路径参数式 DELETE 都会 404。
	mux.Handle("/api/domains/", limitBody(s.authMiddleware(s.handleDomains)))
	mux.Handle("/api/domains/list", limitBody(s.authMiddleware(s.handleDomainList)))
	mux.Handle("/api/domains/test", limitBody(s.authMiddleware(s.handleDomainTest)))
	mux.Handle("/api/domains/wildcard", limitBody(s.authMiddleware(s.handleDomainWildcard)))
	mux.Handle("/api/instances", limitBody(s.authMiddleware(s.handleInstances)))
	// 前缀路由：DELETE /api/instances/{url} 路径参数形式（同上）
	mux.Handle("/api/instances/", limitBody(s.authMiddleware(s.handleInstances)))
	mux.Handle("/api/instances/sync", limitBody(s.authMiddleware(s.handleInstanceSync)))
	mux.Handle("/api/test-instance", limitBody(s.authMiddleware(s.handleTestInstance)))
	mux.Handle("/api/rewrites", limitBody(s.authMiddleware(s.handleRewrites)))
	// 手动维护的自定义重写表（非 Cloudflare 域名）
	mux.Handle("/api/manual-rewrites", limitBody(s.authMiddleware(s.handleManualRewrites)))
	mux.Handle("/api/manual-rewrites/", limitBody(s.authMiddleware(s.handleManualRewrites)))

	return mux
}

// writeJSON 输出 JSON 响应。
func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// handleHealth 无需鉴权的只读健康检查端点（供容器 HEALTHCHECK / 负载均衡探测）。
// 只返回进程存活状态，不暴露任何配置或运行数据。
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "version": version})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	st := s.status
	st.Running = s.running // P0-4：把内部 running 同步进响应
	history := append([]RunRecord(nil), s.history...)
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  st,
		"history": history,
	})
}

// handleConfig GET 返回脱敏配置，POST 更新配置。
func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.mu.Lock()
		snap := s.cfg.Sanitized() // P0-1：密码脱敏
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, snap)
	case http.MethodPost:
		body, err := io.ReadAll(r.Body)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		var in config.Config
		if err := json.Unmarshal(body, &in); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		// P1-1：字段级合并——仅应用请求中显式出现的字段，部分提交（如只保存
		// test_ipv6 开关）不再把未提交字段清零/回填为默认值。
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(body, &raw); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		present := make(map[string]bool, len(raw))
		for k := range raw {
			present[k] = true
		}
		s.mu.Lock()
		prevRunOnStart := s.cfg.RunOnStart
		s.cfg.ApplyUpdateFields(in, present)
		err = s.cfg.Save()
		interval := s.cfg.IntervalMinutes
		runOnStart := s.cfg.RunOnStart
		s.mu.Unlock()
		if err != nil { // H-4：Save 错误可见化
			log.Printf("[错误] 配置保存失败: %v", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "配置保存失败: " + err.Error()})
			return
		}
		// 重启定时器以应用新的间隔
		s.restartScheduler()
		// run_on_start 从关变开时立即触发一次（保存即生效，无需重启）
		if runOnStart && !prevRunOnStart {
			s.triggerRun("manual")
		}
		writeJSON(w, http.StatusOK, map[string]any{"message": "配置已保存", "interval_minutes": interval})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleRun 手动触发一次测速 + 写入。
func (s *Server) handleRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.triggerRun("manual") {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "测速正在进行中"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "测速已开始"})
}

// triggerRun 若当前空闲则异步启动一次测速，返回是否成功启动。
// trigger 标记触发方式（manual / schedule / startup），用于任务历史展示。
func (s *Server) triggerRun(trigger string) bool {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return false
	}
	s.running = true
	s.runners.Add(1) // P0-2：登记在途任务，供优雅关闭等待
	s.mu.Unlock()

	go func() {
		defer func() {
			s.mu.Lock()
			s.running = false
			s.mu.Unlock()
			s.runners.Done()
		}()
		s.runOnce(trigger)
	}()
	return true
}

// WaitRunners 等待全部在途测速任务完成；超过 timeout 则放弃等待并返回 false。
// 供优雅关闭时调用，避免滚动更新时把写入阶段的任务杀在半途。
func (s *Server) WaitRunners(timeout time.Duration) bool {
	c := make(chan struct{})
	go func() {
		s.runners.Wait()
		close(c)
	}()
	select {
	case <-c:
		return true
	case <-time.After(timeout):
		return false
	}
}

// pushHistory 追加一条任务历史（调用方需持锁）。
func (s *Server) pushHistory(rec RunRecord) {
	s.history = append([]RunRecord{rec}, s.history...)
	if len(s.history) > maxRunHistory {
		s.history = s.history[:maxRunHistory]
	}
}

// DomainInfo 描述一个域名的完整信息（含元数据与实例归属）。
type DomainInfo struct {
	Domain    string   `json:"domain"`
	CreatedAt string   `json:"created_at"`
	UpdatedAt string   `json:"updated_at"`
	Wildcard  bool     `json:"wildcard"`  // 包含子域
	Instances []string `json:"instances"` // 配置了该域名的 AdGuard 实例名
}

// handleDomainList 返回带元数据的域名列表（Domains 面板用）。
func (s *Server) handleDomainList(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	cfg := s.cfg.Clone()
	s.mu.Unlock()

	instNames := make([]string, 0, len(cfg.AdguardInstances))
	for _, inst := range cfg.AdguardInstances {
		instNames = append(instNames, inst.Name)
	}

	list := make([]DomainInfo, 0, len(cfg.CustomDomains))
	metaByName := make(map[string]config.DomainMeta, len(cfg.DomainMetas))
	for _, m := range cfg.DomainMetas {
		metaByName[m.Domain] = m
	}
	for _, d := range cfg.CustomDomains {
		info := DomainInfo{Domain: d, Instances: instNames}
		if m, ok := metaByName[d]; ok {
			info.CreatedAt, info.UpdatedAt = m.CreatedAt, m.UpdatedAt
			info.Wildcard = m.Wildcard
		}
		list = append(list, info)
	}
	writeJSON(w, http.StatusOK, map[string]any{"domains": list})
}

// handleDomainWildcard 切换某个域名的「包含子域」开关。
// 切换后立即把该域名的新形式（裸域名 / *.域名）写入全部实例。
func (s *Server) handleDomainWildcard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var in struct {
		Domain   string `json:"domain"`
		Wildcard bool   `json:"wildcard"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || strings.TrimSpace(in.Domain) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "缺少 domain 字段"})
		return
	}
	// 统一为裸域名（CustomDomains 只存裸域名，通配状态记录在 DomainMetas）
	domain := normalizeDomain(in.Domain)

	s.mu.Lock()
	exists := false
	for _, d := range s.cfg.CustomDomains {
		if d == domain {
			exists = true
			break
		}
	}
	if !exists {
		s.mu.Unlock()
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "未找到该域名"})
		return
	}
	// 元数据不存在时自动创建（如 fresh start 时内置的默认域名尚无元数据）
	s.cfg.SetDomainWildcard(domain, in.Wildcard)
	saveErr := s.cfg.Save()
	active := s.activeIP
	results := append([]speedtest.Result(nil), s.status.Results...)
	insts := append([]config.AdguardInstance(nil), s.cfg.AdguardInstances...)
	domains := s.expandDomains(s.cfg.CustomDomains, s.cfg.DomainMetas)
	lastIP := s.cfg.LastResultIP
	s.mu.Unlock()
	reportSaveError(w, saveErr)

	// 立即用新形式重写全部实例（旧形式会被 SyncRewrites 的清理逻辑移除）。
	// P2-1：后台执行，避免单个不可达实例（15s×3 重试）阻塞本次请求。
	ip := active
	if ip == "" && len(results) > 0 {
		ip = results[0].IP
	}
	if ip == "" {
		ip = lastIP // 重启后无内存结果时回退持久化的最近结果
	}
	go func() {
		for _, inst := range insts {
			want := wantForInstance(domains, ip, inst)
			if len(want) == 0 {
				continue
			}
			client := s.providerFor(inst)
			if _, err := client.ReplaceRewrites(want); err != nil {
				log.Printf("[错误] [%s] 更新域名形式失败: %v", inst.Name, err)
			}
		}
	}()
	writeJSON(w, http.StatusOK, map[string]any{"message": "已更新，正在后台同步实例", "domain": domain, "wildcard": in.Wildcard})
}

// handleDomainTest 检测域名是否由 Cloudflare 服务：
// 对该域名发起 TLS 连接并读取证书 + 响应头判断。
func (s *Server) handleDomainTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var in struct {
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || strings.TrimSpace(in.Domain) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "缺少 domain 字段"})
		return
	}
	domain := normalizeDomain(in.Domain)
	result := testCloudflareDomain(domain)
	writeJSON(w, http.StatusOK, result)
}

// testCloudflareDomain 通过 TLS 握手 + HTTPS 响应头检测域名是否由 Cloudflare 服务。
// 两步并行探测，总超时 6 秒——串行执行时最坏 13s+，浏览器 fetch 会直接报
// "failed to fetch"。
func testCloudflareDomain(domain string) map[string]any {
	result := map[string]any{"domain": domain}

	var wg sync.WaitGroup

	// P0-1：两个 goroutine 各写各自的局部 map，wg.Wait() 后由主 goroutine 合并。
	// 直接并发写同一个 map（即使 key 不同）会触发 fatal error: concurrent map writes，
	// 该错误无法 recover，会直接杀死整个进程。

	// 1. TLS 握手：读取证书签发者与有效期
	tlsRes := make(map[string]any)
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", domain+":443", &tls.Config{ServerName: domain})
		if err != nil {
			tlsRes["tls_ok"] = false
			tlsRes["tls_error"] = err.Error()
			return
		}
		state := conn.ConnectionState()
		_ = conn.Close()
		if len(state.PeerCertificates) > 0 {
			cert := state.PeerCertificates[0]
			tlsRes["tls_ok"] = true
			tlsRes["issuer"] = cert.Issuer.CommonName
			tlsRes["not_after"] = cert.NotAfter.Format("2006-01-02")
		} else {
			tlsRes["tls_ok"] = false
		}
	}()

	// 2. HTTPS 请求：检查响应头中的 Cloudflare 特征（server: cloudflare / cf-ray）
	httpRes := make(map[string]any)
	wg.Add(1)
	go func() {
		defer wg.Done()
		client := &http.Client{
			Timeout: 5 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 3 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		}
		req, err := http.NewRequest(http.MethodHead, "https://"+domain, nil)
		if err != nil {
			httpRes["is_cloudflare"] = false
			httpRes["error"] = err.Error()
			return
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.80 Safari/537.36")
		resp, err := client.Do(req)
		if err != nil {
			httpRes["is_cloudflare"] = false
			httpRes["error"] = err.Error()
			return
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)

		server := resp.Header.Get("server")
		cfRay := resp.Header.Get("cf-ray")
		httpRes["status_code"] = resp.StatusCode
		httpRes["server"] = server
		isCF := (strings.EqualFold(server, "cloudflare") || cfRay != "")
		httpRes["is_cloudflare"] = isCF
		if isCF && cfRay != "" {
			// cf-ray 尾部即机场三字码（地区码）
			if i := strings.LastIndex(cfRay, "-"); i >= 0 && i+1 < len(cfRay) {
				httpRes["colo"] = cfRay[i+1:]
			}
		}
	}()

	// 总超时兜底：任一探测卡死也不超过 6 秒返回
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
		for k, v := range tlsRes {
			result[k] = v
		}
		for k, v := range httpRes {
			result[k] = v
		}
	case <-time.After(6 * time.Second):
		if _, ok := result["is_cloudflare"]; !ok {
			result["is_cloudflare"] = false
			result["error"] = "检测超时（6 秒）"
		}
	}
	return result
}

// handleDomains 管理额外域名列表。DELETE 支持路径参数 /api/domains/{name}（M-8），
// 同时兼容请求体 JSON。
func (s *Server) handleDomains(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.mu.Lock()
		domains := append([]string(nil), s.cfg.CustomDomains...)
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"domains": domains})
	case http.MethodPost:
		var in struct {
			Domain string `json:"domain"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil || strings.TrimSpace(in.Domain) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "缺少 domain 字段"})
			return
		}
		domain := normalizeDomain(in.Domain)
		s.mu.Lock()
		exists := false
		for _, d := range s.cfg.CustomDomains {
			if d == domain {
				exists = true
				break
			}
		}
		removedManual := 0
		var affected []config.AdguardInstance
		if !exists {
			s.cfg.CustomDomains = append(s.cfg.CustomDomains, domain)
			s.cfg.SyncDomainMeta(time.Now()) // 同步元数据：新域名记录 CreatedAt
			// 新域名与各实例自定义重写表中的同名条目冲突：删除之（裸与 *. 形式），
			// 随后后台重同步受影响的实例，避免同一域名出现多条记录
			for i := range s.cfg.AdguardInstances {
				inst := &s.cfg.AdguardInstances[i]
				out := inst.ManualRewrites[:0]
				for _, m := range inst.ManualRewrites {
					if m.Domain == domain || m.Domain == "*."+domain {
						removedManual++
						continue
					}
					out = append(out, m)
				}
				if len(out) != len(inst.ManualRewrites) {
					inst.ManualRewrites = out
					affected = append(affected, s.cfg.AdguardInstances[i])
				}
			}
		}
		saveErr := s.cfg.Save()
		domains := append([]string(nil), s.cfg.CustomDomains...)
		s.mu.Unlock()
		reportSaveError(w, saveErr)
		for _, inst := range affected {
			s.syncInstanceBackground(inst)
		}
		writeJSON(w, http.StatusOK, map[string]any{"domains": domains, "removed_manual": removedManual})
	case http.MethodDelete:
		// 路径参数优先：/api/domains/example.com
		domain := strings.TrimPrefix(r.URL.Path, "/api/domains/")
		if domain == "" {
			var in struct {
				Domain string `json:"domain"`
			}
			if err := json.NewDecoder(r.Body).Decode(&in); err == nil {
				domain = in.Domain
			}
		}
		domain = normalizeDomain(domain)
		if domain == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "缺少 domain"})
			return
		}
		s.mu.Lock()
		out := s.cfg.CustomDomains[:0]
		for _, d := range s.cfg.CustomDomains {
			if d != domain {
				out = append(out, d)
			}
		}
		s.cfg.CustomDomains = out
		s.cfg.SyncDomainMeta(time.Now()) // 同步元数据：移除已删域名的记录
		saveErr := s.cfg.Save()
		domains := append([]string(nil), s.cfg.CustomDomains...)
		s.mu.Unlock()
		reportSaveError(w, saveErr)
		// 完全接管：删除域名时立即清掉该域名（含 *. 形式）在全部实例上的重写记录
		s.removeDomainFromInstances(domain)
		writeJSON(w, http.StatusOK, map[string]any{"domains": domains})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// InstanceStatus 描述一个 AdGuard 实例的连接状态。
type InstanceStatus struct {
	Name  string `json:"name"`
	URL   string `json:"url"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	Rules int    `json:"rules,omitempty"` // 当前重写规则数量
	// 一致性状态：synced=与期望一致；drift=有差异；unknown=无法判断（无测速结果等）
	Sync  string   `json:"sync,omitempty"`
	Drift []string `json:"drift,omitempty"` // 差异明细（人类可读）
}

// handleInstances GET 列出全部实例及连通性；POST 添加实例；DELETE 删除实例。
func (s *Server) handleInstances(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.writeInstanceList(w)
	case http.MethodPost:
		var in config.AdguardInstance
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		in.Name = strings.TrimSpace(in.Name)
		in.RulesFile = strings.TrimSpace(in.RulesFile)
		// 文件型实例（dnsmasq/smartdns/mosdns）没有 API 地址，URL 按设计留空；
		// 但查重/删除/定位均以 URL 为键，故用受管规则文件路径合成 file:// 标识充当主键。
		if isFileBasedType(in.Type) {
			if in.RulesFile == "" {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "缺少受管规则文件路径（rules_file）"})
				return
			}
			if !strings.HasPrefix(in.RulesFile, "/") {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "受管规则文件路径必须为容器内绝对路径"})
				return
			}
			in.URL = "file://" + in.RulesFile
		} else {
			in.URL = normalizeInstanceURL(in.URL)
			if in.URL == "" {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "缺少 url 字段"})
				return
			}
		}
		if in.Name == "" {
			in.Name = fmt.Sprintf("实例-%d", len(s.cfg.AdguardInstances)+1)
		}

		// 第一遍查重（锁内快照 + 校验）
		s.mu.Lock()
		for _, inst := range s.cfg.AdguardInstances {
			if inst.URL == in.URL {
				s.mu.Unlock()
				writeJSON(w, http.StatusConflict, map[string]string{"error": "该 URL 的实例已存在"})
				return
			}
		}
		s.mu.Unlock()

		// 接管协商：本工具会接管整张重写表，实例上已有规则时需用户确认处置方式。
		// P1-3：网络探测在锁外执行，避免不可达实例（3 次重试 × 15s 超时）
		// 使全局互斥锁冻结整个 Dashboard。
		client := s.providerFor(in)
		list, listErr := client.ListRewrites()

		switch in.Adopt {
		case "import":
			// 保留：把现有规则读入该实例的自定义重写表（跳过与托管域名重复的，
			// 忽略停用条目），随后整表清空重发
			managed := s.managedDomainSet()
			imported := make([]config.ManualRewrite, 0, len(list))
			seen := make(map[string]bool, len(list))
			for _, ent := range list {
				if !ent.Enabled || ent.Domain == "" || ent.Answer == "" {
					continue
				}
				if managed[ent.Domain] || managed[strings.TrimPrefix(ent.Domain, "*.")] {
					continue // 与托管域名重复，测速同步会写入
				}
				key := ent.Domain + "\x00" + ent.Answer
				if seen[key] {
					continue
				}
				seen[key] = true
				imported = append(imported, config.ManualRewrite{Domain: ent.Domain, Answer: ent.Answer})
			}
			in.ManualRewrites = imported
		case "":
			// 未确认：实例上已有规则时返回 409，让前端弹窗选择「保留/抛弃/取消」
			if listErr == nil && len(list) > 0 {
				writeJSON(w, http.StatusConflict, map[string]any{
					"error":    fmt.Sprintf("该实例上已有 %d 条重写规则，本工具添加后将接管整张重写表，请确认处置方式", len(list)),
					"rewrites": list,
				})
				return
			}
			// listErr != nil：拉不到列表时不阻塞添加，后续写入阶段会报错可见
		}

		// 第二遍查重（锁内），覆盖探测期间并发添加同 URL 的窗口
		s.mu.Lock()
		for _, inst := range s.cfg.AdguardInstances {
			if inst.URL == in.URL {
				s.mu.Unlock()
				writeJSON(w, http.StatusConflict, map[string]string{"error": "该 URL 的实例已存在"})
				return
			}
		}
		s.cfg.AdguardInstances = append(s.cfg.AdguardInstances, in)
		saveErr := s.cfg.Save()
		s.mu.Unlock()
		reportSaveError(w, saveErr)

		// 已确认（或实例本就无规则）：立即整表同步（清空现有 + 下发最优 IP 与手动规则）。
		// 后台执行，避免阻塞请求。
		go s.writeCurrentBestToInstance(in)

		s.writeInstanceList(w)
	case http.MethodDelete:
		url := strings.TrimPrefix(r.URL.Path, "/api/instances")
		if url == "" {
			var in struct {
				URL string `json:"url"`
			}
			if err := json.NewDecoder(r.Body).Decode(&in); err == nil {
				url = in.URL
			}
		}
		url = strings.TrimRight(strings.TrimSpace(url), "/")
		s.mu.Lock()
		out := s.cfg.AdguardInstances[:0]
		for _, inst := range s.cfg.AdguardInstances {
			if inst.URL != url {
				out = append(out, inst)
			}
		}
		s.cfg.AdguardInstances = out
		saveErr := s.cfg.Save()
		s.mu.Unlock()
		reportSaveError(w, saveErr)
		s.writeInstanceList(w)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// expandDomains 把目标域名列表按「包含子域」元数据展开为实际写入的重写域名：
// wildcard=true 时写入 *.<domain>，否则写裸域名。
func (s *Server) expandDomains(customDomains []string, metas []config.DomainMeta) []string {
	wildByName := make(map[string]bool, len(metas))
	for _, m := range metas {
		wildByName[m.Domain] = m.Wildcard
	}
	out := make([]string, 0, len(customDomains))
	for _, d := range customDomains {
		if wildByName[d] {
			out = append(out, "*."+d)
		} else {
			out = append(out, d)
		}
	}
	return out
}

// managedDomainSet 返回全部托管域名形式（裸域名与 *. 形式），用于与手动规则的冲突检查。
func (s *Server) managedDomainSet() map[string]bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	set := map[string]bool{}
	for _, d := range s.expandDomains(s.cfg.CustomDomains, s.cfg.DomainMetas) {
		set[d] = true
		set[strings.TrimPrefix(d, "*.")] = true
	}
	return set
}

// buildWant 构造期望重写集合：每个展开后的域名形式写入指定 IP。
// 包含子域（*.domain）的域名同时写裸域名与通配两条记录；未包含子域的
// 域名把 *. 形式置为空集，SyncRewrites 的接管语义会清除其残留记录。
func buildWant(domains []string, ip string) map[string]map[string]bool {
	want := make(map[string]map[string]bool, len(domains)*2)
	for _, d := range domains {
		want[d] = map[string]bool{ip: true}
		if strings.HasPrefix(d, "*.") {
			want[strings.TrimPrefix(d, "*.")] = map[string]bool{ip: true}
		} else {
			want["*."+d] = map[string]bool{}
		}
	}
	return want
}

// wantForInstance 构造指定实例的期望重写集合：最优 IP 重写（含另一形式清理）+ 该实例独有的手动重写规则。
func wantForInstance(domains []string, ip string, inst config.AdguardInstance) map[string]map[string]bool {
	var want map[string]map[string]bool
	if ip != "" && len(domains) > 0 {
		want = buildWant(domains, ip)
	} else {
		want = map[string]map[string]bool{}
	}
	for _, m := range inst.ManualRewrites {
		if m.Domain == "" || m.Answer == "" {
			continue
		}
		if want[m.Domain] == nil {
			want[m.Domain] = map[string]bool{}
		}
		want[m.Domain][m.Answer] = true
	}
	return want
}

// writeCurrentBestToInstance 把当前生效的最优 IP 立即写入指定实例的全部
// 目标域名；无历史结果时静默跳过（等下轮测速）。
func (s *Server) writeCurrentBestToInstance(inst config.AdguardInstance) {
	s.mu.Lock()
	active := s.activeIP
	results := append([]speedtest.Result(nil), s.status.Results...)
	domains := s.expandDomains(s.cfg.CustomDomains, s.cfg.DomainMetas)
	lastIP := s.cfg.LastResultIP
	s.mu.Unlock()

	ip := active
	if ip == "" && len(results) > 0 {
		ip = results[0].IP // 尚未由守护协程接管时退化为测速最优
	}
	if ip == "" {
		ip = lastIP // 重启后无内存结果时回退持久化的最近结果
	}
	// 接管语义：无论 want 是否为空都执行整表重发（空表 = 清空实例现有规则）
	client := s.providerFor(inst)
	_, err := client.ReplaceRewrites(wantForInstance(domains, ip, inst))
	if err != nil {
		log.Printf("[错误] [%s] 初始化写入失败: %v", inst.Name, err)
		return
	}
	fmt.Printf("[%s] 新实例 %s 初始化写入完成：%s → %d 个域名\n",
		time.Now().Format("2006-01-02 15:04:05"), inst.Name, ip, len(domains))
}

// providerFor 构造指定实例的 DNS Provider；未知类型回退 AdGuard（兼容旧配置）。
func (s *Server) providerFor(inst config.AdguardInstance) dns.Provider {
	p, err := dns.New(inst)
	if err != nil {
		log.Printf("[警告] 实例 %s 类型 %q 未知，按 AdGuard 处理", inst.Name, inst.Type)
		return dns.NewAdGuard(inst)
	}
	return p
}

// instances 返回实例快照（调用方需持锁或接受快照语义）。
func (s *Server) instances() []config.AdguardInstance {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]config.AdguardInstance(nil), s.cfg.AdguardInstances...)
}

// expectedRewritesFor 计算指定实例期望的完整重写集合：
// 每个目标域名 → 当前生效的最优 IP（单条）+ 该实例独有的手动规则。
// 第二个返回值 false 表示该实例没有任何可写内容。
func (s *Server) expectedRewritesFor(inst config.AdguardInstance) (map[string]map[string]bool, bool) {
	s.mu.Lock()
	active := s.activeIP
	results := append([]speedtest.Result(nil), s.status.Results...)
	domains := s.expandDomains(s.cfg.CustomDomains, s.cfg.DomainMetas)
	lastIP := s.cfg.LastResultIP
	s.mu.Unlock()

	ip := active
	if ip == "" && len(results) > 0 {
		ip = results[0].IP // 尚未由守护协程接管时退化为测速最优
	}
	if ip == "" {
		ip = lastIP // 重启后无内存结果时回退持久化的最近结果
	}
	want := wantForInstance(domains, ip, inst)
	if len(want) == 0 {
		return nil, false
	}
	return want, true
}

// diffInstance 对比实例上的重写与期望集合，返回差异明细：
// 缺失的（期望有但实例没有或指向旧 IP）、多余的（实例有但不在期望内且属于我们管理的域名）。
func diffInstance(list []dns.RewriteEntry, want map[string]map[string]bool) []string {
	var drift []string
	actual := make(map[string]map[string]bool)
	for _, ent := range list {
		if _, managed := want[ent.Domain]; !managed {
			continue // 非我们管理的域名不参与比对
		}
		if actual[ent.Domain] == nil {
			actual[ent.Domain] = map[string]bool{}
		}
		actual[ent.Domain][ent.Answer] = true
	}
	for d, answers := range want {
		have := actual[d]
		for ip := range answers {
			if have == nil || !have[ip] {
				drift = append(drift, fmt.Sprintf("%s 缺少 → %s", d, ip))
			}
		}
		for ip := range have {
			if !answers[ip] {
				drift = append(drift, fmt.Sprintf("%s 过期值 → %s", d, ip))
			}
		}
	}
	return drift
}

// writeInstanceList 检查每个实例连通性 + 重写一致性后输出列表。
func (s *Server) writeInstanceList(w http.ResponseWriter) {
	insts := s.instances()
	result := make([]InstanceStatus, 0, len(insts))
	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, inst := range insts {
		wg.Add(1)
		go func(i config.AdguardInstance) {
			defer wg.Done()
			st := InstanceStatus{Name: i.Name, URL: i.URL}
			c := s.providerFor(i)
			list, err := c.ListRewrites()
			if err != nil {
				st.Error = err.Error()
			} else {
				st.OK = true
				st.Rules = len(list)
				if want, ok := s.expectedRewritesFor(i); ok {
					drift := diffInstance(list, want)
					if len(drift) == 0 {
						st.Sync = "synced"
					} else {
						st.Sync = "drift"
						st.Drift = drift
					}
				} else {
					st.Sync = "unknown"
				}
			}
			mu.Lock()
			result = append(result, st)
			mu.Unlock()
		}(inst)
	}
	wg.Wait()
	writeJSON(w, http.StatusOK, map[string]any{"instances": result})
}

// syncJob 描述一次实例同步任务的执行状态（P1-7）。
// 同步可能耗时数分钟（每实例串行重试），超过 WriteTimeout 会导致响应丢失
// 但后台仍在继续写；改为异步任务 + 前端轮询解决。
type syncJob struct {
	running bool
	results []syncResult
	doneAt  string
}

// syncResult 单个实例的同步结果。
type syncResult struct {
	Name    string `json:"name"`
	URL     string `json:"url"`
	Written int    `json:"written"`
	Removed int    `json:"removed"`
	Error   string `json:"error,omitempty"`
}

// handleInstanceSync 实例同步（异步化）：
//   - POST：启动后台同步任务；已有任务在跑时返回 409；
//   - GET：查询最近一次/进行中任务的状态与结果（前端轮询用）。
func (s *Server) handleInstanceSync(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.mu.Lock()
		job := s.syncState
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{
			"running": job.running,
			"results": job.results,
			"done_at": job.doneAt,
		})
	case http.MethodPost:
		wantURL := strings.TrimRight(strings.TrimSpace(r.URL.Query().Get("url")), "/")

		insts := s.instances()
		targets := make([]config.AdguardInstance, 0, len(insts))
		for _, inst := range insts {
			if wantURL == "" || inst.URL == wantURL {
				targets = append(targets, inst)
			}
		}
		if len(targets) == 0 {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "未找到指定实例"})
			return
		}

		s.mu.Lock()
		if s.syncState.running {
			s.mu.Unlock()
			writeJSON(w, http.StatusConflict, map[string]string{"error": "同步任务正在进行中，请稍候"})
			return
		}
		s.syncState = syncJob{running: true}
		s.mu.Unlock()

		go func() {
			results := s.runSync(targets)
			now := time.Now().Format("2006-01-02 15:04:05")
			s.mu.Lock()
			s.syncState = syncJob{running: false, results: results, doneAt: now}
			s.mu.Unlock()
		}()
		writeJSON(w, http.StatusAccepted, map[string]any{"started": true})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// runSync 执行实际的同步逻辑（后台 goroutine 中调用）：把每个实例
// 期望的重写集合（最优 IP + 该实例独有手动规则）整表下发。
func (s *Server) runSync(targets []config.AdguardInstance) []syncResult {
	results := make([]syncResult, 0, len(targets))
	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, inst := range targets {
		wg.Add(1)
		go func(i config.AdguardInstance) {
			defer wg.Done()
			res := syncResult{Name: i.Name, URL: i.URL}
			want, ok := s.expectedRewritesFor(i)
			if !ok {
				res.Error = "尚无测速结果且无手动规则，无法同步"
				mu.Lock()
				results = append(results, res)
				mu.Unlock()
				return
			}
			client := s.providerFor(i)
			stats, err := client.ReplaceRewrites(want)
			if err != nil {
				log.Printf("[错误] [%s] 同步失败: %v", i.Name, err)
				res.Error = err.Error()
				res.Written = stats.Written
				res.Removed = stats.Removed
			} else {
				res.Written = stats.Written
				res.Removed = stats.Removed
			}
			mu.Lock()
			results = append(results, res)
			mu.Unlock()
		}(inst)
	}
	wg.Wait()
	return results
}

// isFileBasedType 文件型实例类型判定（无在线管理 API，经受管规则文件写入）。
func isFileBasedType(t string) bool {
	switch t {
	case "dnsmasq", "smartdns", "mosdns":
		return true
	default:
		return false
	}
}

// normalizeInstanceURL 规范化实例地址：trim + 去尾部斜杠；
// 用户忘记写协议头时自动补 http://。
func normalizeInstanceURL(url string) string {
	url = strings.TrimRight(strings.TrimSpace(url), "/")
	if url != "" && !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "http://" + url
	}
	return url
}

// handleTestInstance 测试单个 AdGuard Home 实例连接（不保存）。
func (s *Server) handleTestInstance(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var in config.AdguardInstance
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if in.Type == "" {
		in.Type = "adguard"
	}
	c, err := dns.New(in)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	if err := c.TestConnection(); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleRewrites 列出某个 AdGuard Home 实例当前的重写规则（?url= 指定，缺省第一个）。
func (s *Server) handleRewrites(w http.ResponseWriter, r *http.Request) {
	wantURL := strings.TrimRight(strings.TrimSpace(r.URL.Query().Get("url")), "/")
	insts := s.instances()
	var chosen *config.AdguardInstance
	for i := range insts {
		if wantURL == "" || insts[i].URL == wantURL {
			chosen = &insts[i]
			break
		}
	}
	if chosen == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "未找到指定实例"})
		return
	}
	c := s.providerFor(*chosen)
	list, err := c.ListRewrites()
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"rewrites": list})
}

// findInstance 按 URL 定位实例（?url= 缺省第一个）。返回 nil 表示未找到。
func (s *Server) findInstance(url string) *config.AdguardInstance {
	insts := s.instances()
	for i := range insts {
		if url == "" || insts[i].URL == url {
			return &insts[i]
		}
	}
	return nil
}

// handleManualRewrites 管理指定实例（?url=）独有的手动重写表：
//   - GET 列出；
//   - POST {domain, answer} 添加（自动去重，保存后后台同步该实例）；
//   - DELETE /api/manual-rewrites/{domain}?answer=xxx 删除（保存后后台同步该实例）。
func (s *Server) handleManualRewrites(w http.ResponseWriter, r *http.Request) {
	wantURL := strings.TrimRight(strings.TrimSpace(r.URL.Query().Get("url")), "/")
	inst := s.findInstance(wantURL)
	if inst == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "未找到指定实例"})
		return
	}

	// 托管域名集合（裸域名与 *. 形式），手动规则不允许与其冲突
	managedSet := s.managedDomainSet()

	switch r.Method {
	case http.MethodGet:
		list := inst.ManualRewrites
		if list == nil {
			list = []config.ManualRewrite{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"rewrites": list})
	case http.MethodPost:
		var in config.ManualRewrite
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		in.Domain = normalizeDomain(in.Domain)
		in.Answer = strings.TrimSpace(in.Answer)
		if in.Domain == "" || in.Answer == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "domain 与 answer 均不能为空"})
			return
		}
		if managedSet[in.Domain] || managedSet["*."+in.Domain] {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "该域名由测速自动管理，无需手动添加"})
			return
		}

		s.mu.Lock()
		dup := false
		for _, m := range s.cfg.AdguardInstances {
			if m.URL != inst.URL {
				continue
			}
			for _, e := range m.ManualRewrites {
				if e.Domain == in.Domain && e.Answer == in.Answer {
					dup = true
					break
				}
			}
			break
		}
		if !dup {
			for i := range s.cfg.AdguardInstances {
				if s.cfg.AdguardInstances[i].URL == inst.URL {
					s.cfg.AdguardInstances[i].ManualRewrites = append(s.cfg.AdguardInstances[i].ManualRewrites, in)
					break
				}
			}
		}
		saveErr := s.cfg.Save()
		snap := s.findInstanceLocked(inst.URL)
		s.mu.Unlock()
		if saveErr != nil {
			log.Printf("[错误] 配置保存失败: %v", saveErr)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "配置保存失败: " + saveErr.Error()})
			return
		}
		// 后台把该实例的重写表整表重发（含新手动规则）
		if snap != nil {
			s.syncInstanceBackground(*snap)
		}
		writeJSON(w, http.StatusOK, map[string]any{"rewrites": s.manualRewritesOf(inst.URL)})
	case http.MethodDelete:
		domain := normalizeDomain(strings.TrimPrefix(r.URL.Path, "/api/manual-rewrites/"))
		answer := strings.TrimSpace(r.URL.Query().Get("answer"))
		if domain == "" || answer == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "缺少 domain 或 answer 参数"})
			return
		}
		s.mu.Lock()
		removed := false
		for i := range s.cfg.AdguardInstances {
			if s.cfg.AdguardInstances[i].URL != inst.URL {
				continue
			}
			out := s.cfg.AdguardInstances[i].ManualRewrites[:0]
			for _, m := range s.cfg.AdguardInstances[i].ManualRewrites {
				if m.Domain == domain && m.Answer == answer {
					removed = true
					continue
				}
				out = append(out, m)
			}
			s.cfg.AdguardInstances[i].ManualRewrites = out
			break
		}
		saveErr := s.cfg.Save()
		snap := s.findInstanceLocked(inst.URL)
		s.mu.Unlock()
		if saveErr != nil {
			log.Printf("[错误] 配置保存失败: %v", saveErr)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "配置保存失败: " + saveErr.Error()})
			return
		}
		if removed && snap != nil {
			s.syncInstanceBackground(*snap)
		}
		writeJSON(w, http.StatusOK, map[string]any{"rewrites": s.manualRewritesOf(inst.URL)})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// findInstanceLocked 在持锁状态下按 URL 查找实例（需调用方持有 s.mu）。
func (s *Server) findInstanceLocked(url string) *config.AdguardInstance {
	for i := range s.cfg.AdguardInstances {
		if s.cfg.AdguardInstances[i].URL == url {
			return &s.cfg.AdguardInstances[i]
		}
	}
	return nil
}

// manualRewritesOf 返回指定实例当前的手动重写表快照（保证非 nil）。
func (s *Server) manualRewritesOf(url string) []config.ManualRewrite {
	s.mu.Lock()
	defer s.mu.Unlock()
	if inst := s.findInstanceLocked(url); inst != nil && inst.ManualRewrites != nil {
		return append([]config.ManualRewrite(nil), inst.ManualRewrites...)
	}
	return []config.ManualRewrite{}
}

// syncInstanceBackground 后台把指定实例的重写表整表重发（含其手动规则）。
func (s *Server) syncInstanceBackground(inst config.AdguardInstance) {
	go func() {
		s.mu.Lock()
		active := s.activeIP
		results := append([]speedtest.Result(nil), s.status.Results...)
		domains := s.expandDomains(s.cfg.CustomDomains, s.cfg.DomainMetas)
		lastIP := s.cfg.LastResultIP
		s.mu.Unlock()
		ip := active
		if ip == "" && len(results) > 0 {
			ip = results[0].IP
		}
		if ip == "" {
			ip = lastIP // 重启后无内存结果时回退持久化的最近结果
		}
		client := s.providerFor(inst)
		if _, err := client.ReplaceRewrites(wantForInstance(domains, ip, inst)); err != nil {
			log.Printf("[错误] [%s] 手动规则同步失败: %v", inst.Name, err)
		} else {
			fmt.Printf("[%s] [%s] 重写表已同步（含手动规则）\n", time.Now().Format("2006-01-02 15:04:05"), inst.Name)
		}
	}()
}

// runOnce 执行一次完整流程：测速 -> 取最快 IP -> 写入所有实例的所有目标域名重写。
// trigger 为触发方式（manual / schedule / startup），用于任务历史展示。
func (s *Server) runOnce(trigger string) {
	startTime := time.Now()

	s.mu.Lock()
	cfg := s.cfg.Clone()
	s.mu.Unlock()

	fmt.Printf("\n[%s] 开始测速...（触发方式：%s）\n", startTime.Format("2006-01-02 15:04:05"), trigger)

	// 实时进度回调：把阶段/正在测试的地址推入 status，供前端轮询展示
	onProgress := func(p speedtest.Progress) {
		s.mu.Lock()
		s.status.Running = true
		s.status.Progress = &p
		s.mu.Unlock()
	}

	results, err := speedtest.Run(speedtest.Options{
		IPFile:          cfg.IPFile,
		Port:            cfg.Port,
		Httping:         cfg.Httping,
		CFColo:          cfg.CFColo,
		MaxDelayMs:      cfg.MaxDelay,
		MinSpeedMBps:    cfg.MinSpeed,
		TestCount:       cfg.TestCount,
		PingTimes:       cfg.PingTimes,
		Routines:        cfg.Routines,
		TestAll:         cfg.TestAll,
		DisableDownload: cfg.DisableDownload,
		URL:             cfg.TestURL,
	}, onProgress)

	now := time.Now().Format("2006-01-02 15:04:05")
	st := Status{
		Running:        false,
		LastRunTime:    now,
		Results:        []speedtest.Result{},
		WrittenDomains: []WrittenDomain{},
	}
	record := RunRecord{Time: now, Trigger: trigger}
	finish := func() {
		record.DurationS = time.Since(startTime).Seconds()
		s.mu.Lock()
		s.status = st
		s.pushHistory(record)
		s.mu.Unlock()
	}
	if err != nil {
		// P2-8：失败时保留上一次的成功结果（BestIP/Results），仅追加错误信息。
		// 用空 st 覆盖会导致首页最优节点与一致性检查全部退化为 unknown，误导排障。
		s.mu.Lock()
		prev := s.status
		s.mu.Unlock()
		st.BestIP = prev.BestIP
		st.BestDelayMs = prev.BestDelayMs
		st.BestSpeedMBps = prev.BestSpeedMBps
		st.BestColo = prev.BestColo
		if len(prev.Results) > 0 {
			st.Results = prev.Results
		}
		st.LastError = err.Error()
		record.Error = err.Error()
		finish()
		fmt.Printf("[%s] 测速失败: %v\n", now, err)
		return
	}
	// IPv6 测速启用时（TestIPv6），在 IPv4 测速完成后追加一轮 IPv6 测速并合并结果
	allResults := results
	if cfg.TestIPv6 {
		// P2-10：ipv6.txt 跟随 cfg.IPFile 所在目录，非 Docker 部署时不再依赖 CWD
		v6File := "ipv6.txt"
		if dir := filepath.Dir(cfg.IPFile); dir != "." && dir != "" {
			v6File = filepath.Join(dir, "ipv6.txt")
		}
		onProgress(speedtest.Progress{Phase: "ping", PhaseLabel: "IPv6 测速中", Current: 0, Total: 0})
		v6Results, err6 := speedtest.Run(speedtest.Options{
			IPFile:       v6File,
			Port:         cfg.Port,
			Httping:      cfg.Httping,
			CFColo:       cfg.CFColo,
			MaxDelayMs:   cfg.MaxDelay,
			MinSpeedMBps: cfg.MinSpeed,
			TestCount:    cfg.TestCount,
			PingTimes:    cfg.PingTimes,
			Routines:     cfg.Routines,
			TestAll:      false, // IPv6 段太大，固定随机采样
			URL:          cfg.TestURL,
			// 与 IPv4 一致：启用下载测速时 IPv6 同样测下载
			DisableDownload: cfg.DisableDownload,
		}, onProgress)
		if err6 != nil {
			fmt.Printf("[%s] IPv6 测速跳过: %v\n", now, err6)
		} else {
			allResults = append(allResults, v6Results...)
			sort.SliceStable(allResults, func(i, j int) bool {
				// 启用下载测速时按速度排名（与 IPv4 轮一致），速度相同再比丢包/延迟
				if !cfg.DisableDownload {
					if allResults[i].SpeedMBps != allResults[j].SpeedMBps {
						return allResults[i].SpeedMBps > allResults[j].SpeedMBps
					}
				}
				if allResults[i].LossRate != allResults[j].LossRate {
					return allResults[i].LossRate < allResults[j].LossRate
				}
				return allResults[i].DelayMs < allResults[j].DelayMs
			})
		}
	}

	st.Results = allResults
	best, ok := speedtest.Best(allResults)
	if !ok {
		st.LastError = "没有可用结果"
		record.Error = "没有可用结果"
		finish()
		return
	}
	st.BestIP = best.IP
	st.BestDelayMs = best.DelayMs
	st.BestSpeedMBps = best.SpeedMBps
	st.BestColo = best.Colo
	// 只保留 Top N 结果：test_all 时全量结果可达数万条，
	// 全量驻留内存并随每次状态轮询序列化返回既浪费内存也浪费带宽。
	if len(allResults) > maxStatusResults {
		allResults = allResults[:maxStatusResults]
	}
	st.Results = allResults

	// 组装要写入重写的域名列表（按「包含子域」元数据展开为实际写入形式）
	domains := s.expandDomains(cfg.CustomDomains, cfg.DomainMetas)

	// 写入策略：每个域名只写最快的 1 个 IP。
	// AdGuard Home 的 rewrite 规则不支持同域名多条记录，多 IP 写入无意义；
	// 备援由可达性守护协程负责（当前 IP 不可达时轮换到上次测速的 #2/#3...）。
	bestIP := best.IP

	// 写入全部 AdGuard Home 实例（互为备份）。
	// 每个实例的期望集合 = 最优 IP 重写 + 该实例独有手动规则，整表下发。
	fmt.Printf("[%s] 最快 IP: %s，开始写入 %d 个 AdGuard Home 实例 × %d 个域名...\n",
		now, bestIP, len(cfg.AdguardInstances), len(domains))

	// 写入阶段进度上报（按实例推进）
	writeTotal := len(cfg.AdguardInstances)
	writeDone := 0
	onProgress(speedtest.Progress{Phase: "writing", PhaseLabel: "写入 AdGuard 重写规则", Current: 0, Total: writeTotal})

	for _, inst := range cfg.AdguardInstances {
		onProgress(speedtest.Progress{Phase: "writing", PhaseLabel: "写入 AdGuard 重写规则",
			Current: writeDone, Total: writeTotal, Detail: fmt.Sprintf("实例 %s", inst.Name)})
		client := s.providerFor(inst)
		stats, err := client.ReplaceRewrites(wantForInstance(domains, bestIP, inst))
		if err != nil {
			fmt.Printf("[%s] [%s] 写入重写失败: %v\n", now, inst.Name, err)
			st.WrittenDomains = append(st.WrittenDomains, WrittenDomain{
				Instance: inst.Name,
				Domain:   strings.Join(domains, ", "),
				Time:     now,
				Error:    err.Error(),
			})
		} else {
			fmt.Printf("[%s] [%s] 写入完成：新增/更新 %d 条，清理过期 %d 条\n", now, inst.Name, stats.Written, stats.Removed)
			for _, d := range domains {
				st.WrittenDomains = append(st.WrittenDomains, WrittenDomain{
					Instance: inst.Name,
					Domain:   d,
					Time:     now,
				})
			}
		}
		writeDone++
	}
	onProgress(speedtest.Progress{Phase: "writing", PhaseLabel: "写入 AdGuard 重写规则", Current: writeTotal, Total: writeTotal})

	record.OK = true
	record.BestIP = best.IP
	record.DelayMs = best.DelayMs
	record.SpeedMBps = best.SpeedMBps
	record.Colo = best.Colo
	record.Written = len(st.WrittenDomains)
	// 保存该次任务的 Top 20 结果，供任务详情弹窗展示
	if len(st.Results) > 20 {
		record.Results = st.Results[:20]
	} else {
		record.Results = st.Results
	}

	// 持久化最近结果；守护协程接管新最优 IP，重置退避状态。
	// 注意：finish() 内部会加 s.mu，此处不能在持锁状态下调用（互斥锁不可重入），
	// 否则自死锁导致全部 API 卡死。改为先更新共享状态、解锁后再 finish()。
	s.mu.Lock()
	s.cfg.LastResultIP = best.IP
	s.cfg.LastResultTime = now
	s.activeIP = best.IP
	s.failStreak = 0
	s.backoffUntil = time.Time{}
	saveErr := s.cfg.Save()
	s.mu.Unlock()
	finish()
	if saveErr != nil {
		log.Printf("[错误] 配置保存失败: %v", saveErr)
	}

	fmt.Printf("[%s] 测速完成，最快 IP: %s (延迟 %.1fms, 速度 %.2f MB/s)，共写入 %d 条\n",
		now, best.IP, best.DelayMs, best.SpeedMBps, len(st.WrittenDomains))
}

// RunOnceAndWait 执行一次测速并写入后返回（供 -once 模式 / cron 使用）。
func (s *Server) RunOnceAndWait() {
	s.runOnce("manual")
}

// StartScheduler 启动定时测速；若配置了 run_on_start 则立即执行一次（M-7）。
// 同时启动可达性守护协程（每分钟探测当前生效 IP，不可达时轮换备选）。
func (s *Server) StartScheduler() {
	s.restartScheduler()
	s.StartWatchdog()

	s.mu.Lock()
	runOnStart := s.cfg.RunOnStart
	s.mu.Unlock()
	if runOnStart {
		s.triggerRun("startup") // 内部会检查 running 状态，忙时跳过
	}
}

// watchdogInterval 守护协程的探测周期。
const watchdogInterval = time.Minute

// maxBackoff 指数退避的上限：连续失败封顶 60 分钟。
const maxBackoff = 60 * time.Minute

// probeAlive 对 IP 做一次 TCP 可达性探测（复用测速端口）。
func (s *Server) probeAlive(ip string) bool {
	s.mu.Lock()
	port := s.cfg.Port
	s.mu.Unlock()
	if port <= 0 {
		port = 443
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, fmt.Sprint(port)), 3*time.Second)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// candidateIPs 返回上次测速结果中的候选 IP 序列（按排名，最多取前 5 个）。
func (s *Server) candidateIPs() []string {
	s.mu.Lock()
	results := append([]speedtest.Result(nil), s.status.Results...)
	s.mu.Unlock()
	ips := make([]string, 0, 5)
	for _, r := range results {
		if len(ips) >= 5 {
			break
		}
		ips = append(ips, r.IP)
	}
	return ips
}

// writeIPToInstances 把指定 IP 写入全部实例的全部管理域名（守护协程轮换用）。
func (s *Server) writeIPToInstances(ip string) bool {
	domains := s.managedDomains()
	if len(domains) == 0 {
		return true // 无域名可写，视为成功
	}
	okAll := true
	for _, inst := range s.instances() {
		client := s.providerFor(inst)
		if _, err := client.ReplaceRewrites(wantForInstance(domains, ip, inst)); err != nil {
			log.Printf("[错误] [守护] [%s] 轮换写入 %s 失败: %v", inst.Name, ip, err)
			okAll = false
		}
	}
	return okAll
}

// managedDomains 返回展开后的全部管理域名。
func (s *Server) managedDomains() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.expandDomains(s.cfg.CustomDomains, s.cfg.DomainMetas)
}

// removeDomainFromInstances 后台删除某域名（含 *. 通配形式）在全部实例上的重写记录。
// 域名从配置移除后不再参与整表收敛，必须在此显式清除，避免残留：
// 以「仅含该域名空集」的期望集合整表重发，各 provider 按自身语义清除对应记录。
func (s *Server) removeDomainFromInstances(domain string) {
	insts := s.instances()
	if len(insts) == 0 {
		return
	}
	go func() {
		for _, inst := range insts {
			client := s.providerFor(inst)
			want := map[string]map[string]bool{
				domain:        {},
				"*." + domain: {},
			}
			if _, err := client.ReplaceRewrites(want); err != nil {
				log.Printf("[错误] [%s] 删除域名 %s 的重写记录失败: %v", inst.Name, domain, err)
			}
		}
		fmt.Printf("[%s] 已从 %d 个实例清理域名 %s 的重写记录\n",
			time.Now().Format("2006-01-02 15:04:05"), len(insts), domain)
	}()
}

// StartWatchdog 启动可达性守护协程：
//   - 每分钟 TCP 探测当前生效 IP；
//   - 不可达则依次轮换上次测速的 #2~#5；
//   - 前 5 名全部不可达则触发重新测速；
//   - 测速无可用结果时按指数退避（1→2→4→…→60 分钟）重试。
func (s *Server) StartWatchdog() {
	s.mu.Lock()
	if s.watchdogStop != nil {
		s.mu.Unlock()
		return // 已在运行
	}
	stop := make(chan struct{})
	s.watchdogStop = stop
	s.mu.Unlock()

	go func() {
		ticker := time.NewTicker(watchdogInterval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				s.watchdogOnce()
			}
		}
	}()
	fmt.Println("可达性守护已启动：每分钟探测当前生效 IP，故障时自动轮换备选")
}

// StopWatchdog 停止守护协程（供测试与优雅关闭使用）。
func (s *Server) StopWatchdog() {
	s.mu.Lock()
	if s.watchdogStop != nil {
		close(s.watchdogStop)
		s.watchdogStop = nil
	}
	s.mu.Unlock()
}

// watchdogOnce 执行一轮探测与故障处理。所有分支都保证不阻塞超过数秒。
func (s *Server) watchdogOnce() {
	// 退避期内不动作
	s.mu.Lock()
	inBackoff := time.Now().Before(s.backoffUntil)
	active := s.activeIP
	running := s.running
	s.mu.Unlock()
	if inBackoff || running {
		return
	}
	if active == "" {
		// 尚无生效 IP：若已有测速结果则接管最优，否则等首次测速完成
		ips := s.candidateIPs()
		if len(ips) == 0 {
			return
		}
		s.mu.Lock()
		s.activeIP = ips[0]
		s.mu.Unlock()
		active = ips[0]
		fmt.Printf("[守护] 接管当前最优 IP: %s\n", active)
	}

	if s.probeAlive(active) {
		return // 一切正常
	}
	fmt.Printf("[守护] 当前生效 IP %s 不可达，尝试轮换备选...\n", active)

	// 依次尝试上次测速的 #2~#5（跳过当前已失效的 active）
	for _, cand := range s.candidateIPs() {
		if cand == active {
			continue
		}
		if s.probeAlive(cand) {
			fmt.Printf("[守护] 轮换到备选 IP: %s\n", cand)
			if s.writeIPToInstances(cand) {
				s.mu.Lock()
				s.activeIP = cand
				s.failStreak = 0
				s.backoffUntil = time.Time{}
				s.mu.Unlock()
			}
			return
		}
	}

	// 前 5 名全部不可达：触发重新测速（指数退避）
	s.mu.Lock()
	s.failStreak++
	backoff := time.Duration(1<<uint(s.failStreak-1)) * time.Minute // 1,2,4,... 封顶 60 分钟
	if backoff > maxBackoff {
		backoff = maxBackoff
	}
	s.backoffUntil = time.Now().Add(backoff)
	streak := s.failStreak
	s.mu.Unlock()
	fmt.Printf("[守护] 上次测速前 5 名均不可达，触发重新测速（第 %d 次，下次退避 %s）\n", streak, backoff)
	if !s.triggerRun("watchdog") {
		log.Printf("[守护] 触发测速失败：已有任务在运行")
	}
}

// restartScheduler 根据当前配置的间隔重启定时器。
// 间隔未变化时直接返回：自动保存每次都会调用本函数，无条件重启会
// 重置测速倒计时并刷屏「定时测速已启动」日志。
func (s *Server) restartScheduler() {
	s.mu.Lock()
	defer s.mu.Unlock()
	interval := s.cfg.IntervalMinutes
	if interval < 0 {
		interval = 0
	}
	if s.schedInterval == interval {
		return
	}
	s.schedInterval = interval
	if s.stopChan != nil {
		close(s.stopChan)
		s.stopChan = nil
	}
	if s.ticker != nil {
		s.ticker.Stop()
		s.ticker = nil
	}
	if interval <= 0 {
		fmt.Println("自动测速已关闭（interval_minutes <= 0）")
		return
	}
	stop := make(chan struct{})
	s.stopChan = stop
	s.ticker = time.NewTicker(time.Duration(interval) * time.Minute)
	go func(t *time.Ticker, stop chan struct{}) {
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				s.triggerRun("schedule") // 忙时自动跳过本轮
			}
		}
	}(s.ticker, stop)
	fmt.Printf("定时测速已启动，间隔 %d 分钟\n", interval)
}

// normalizeDomain 统一域名格式：trim + 小写。
func normalizeDomain(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// reportSaveError 将 Save 错误记录日志（H-4：不再静默吞掉）。
func reportSaveError(w http.ResponseWriter, err error) {
	if err != nil {
		log.Printf("[错误] 配置保存失败: %v", err)
	}
}
