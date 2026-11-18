package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// AdguardInstance 描述一个 DNS 实例（支持多实例同步写入，互为备份）。
// 字段名保留 AdguardInstance 以兼容旧配置文件；Type 区分具体产品。
type AdguardInstance struct {
	Name     string `json:"name"`           // 实例名称（自定义，如 "主"、"备"）
	Type     string `json:"type,omitempty"` // 实例类型：adguard（默认）/ technitium / dnsmasq / smartdns / mosdns
	URL      string `json:"url"`            // API 型：例如 http://192.168.1.2:3000；文件型：留空或备注
	Username string `json:"username"`       // 用户名
	Password string `json:"password"`       // 密码 / API Token

	// 文件型实例（dnsmasq/smartdns/mosdns）专用：
	RulesFile string `json:"rules_file,omitempty"` // 受管规则文件绝对路径
	ReloadCmd string `json:"reload_cmd,omitempty"` // 规则写入后执行的加载命令（可选，如重启服务）

	// 该实例独有的手动重写规则（非 Cloudflare 域名），同步时与最优 IP 重写合并整表下发
	ManualRewrites []ManualRewrite `json:"manual_rewrites,omitempty"`

	// Adopt 仅用于添加请求，表示用户对「接管整张重写表」的确认方式：
	// ""（未确认，后端发现实例已有规则时返回 409 让前端弹窗）、
	// "discard"（抛弃现有规则）、"import"（把现有规则导入自定义重写表）。
	// 不持久化（json:"-"），保存后始终为空。
	Adopt string `json:"adopt,omitempty"`
}

// DomainMeta 描述一个自定义域名的元数据。
type DomainMeta struct {
	Domain    string `json:"domain"`     // 域名
	CreatedAt string `json:"created_at"` // 首次配置时间
	UpdatedAt string `json:"updated_at"` // 最近更新时间
	Wildcard  bool   `json:"wildcard"`   // 包含子域（写入 *.<domain> 通配规则）
}

// ManualRewrite 一条用户手动维护的重写规则（非 Cloudflare 域名）。
// 同步实例时与测速最优 IP 的重写规则合并后整表重发。
type ManualRewrite struct {
	Domain string `json:"domain"` // 重写域名（如 nas.example.com）
	Answer string `json:"answer"` // 解析目标（IP 或域名）
}

// Config 是 cf-dns-select 的全部配置，持久化为 JSON 文件（挂载进容器即可保留）。
// 注意：并发访问由 web.Server 的互斥锁保护，本结构体不内嵌锁（避免拷贝锁问题）。
type Config struct {
	// AdGuardHome 实例列表（全部实例都会被写入相同的重写规则）
	AdguardInstances []AdguardInstance `json:"adguard_instances"`

	// 测速参数（与 CloudflareSpeedTest 参数一一对应）
	IPFile          string  `json:"ip_file"`          // IP 段数据文件（默认 ip.txt）
	Port            int     `json:"port"`             // 测速端口（默认 443）
	Httping         bool    `json:"httping"`          // 是否使用 HTTPing 模式
	CFColo          string  `json:"cfcolo"`           // HTTPing 模式下匹配的地区码，逗号分隔
	MaxDelay        int     `json:"max_delay"`        // 平均延迟上限 ms（0 表示不过滤）
	MinSpeed        float64 `json:"min_speed"`        // 下载速度下限 MB/s（0 表示不过滤）
	TestCount       int     `json:"test_count"`       // 下载测速数量（默认 10）
	PingTimes       int     `json:"ping_times"`       // 延迟测速次数（默认 4）
	Routines        int     `json:"routines"`         // 延迟测速线程数（默认 200）
	TestAll         bool    `json:"test_all"`         // 测速全部 IP（否则每个 /24 随机取一个）
	DisableDownload bool    `json:"disable_download"` // 禁用下载测速
	TestURL         string  `json:"test_url"`         // 测速地址（HTTPing/下载测速共用，留空使用默认地址）

	// 调度配置
	IntervalMinutes int          `json:"interval_minutes"`       // 自动测速间隔（分钟），<=0 表示不自动测速
	RunOnStart      bool         `json:"run_on_start"`           // 启动后立即执行一次测速
	CustomDomains   []string     `json:"custom_domains"`         // 额外要写入 DNS 重写的域名列表（如 openrouter.ai）
	DomainMetas     []DomainMeta `json:"domain_metas,omitempty"` // 域名元数据（与 CustomDomains 一一对应）

	// 写入策略
	TestIPv6 bool `json:"test_ipv6"` // IPv6 是否参与测速与最优排名（与 IPv4 合并取最快；唯一开关）

	// 运行状态（持久化便于重启后回显）
	LastResultIP   string `json:"last_result_ip,omitempty"`  // IPv4 地址族优选结果（双栈关闭时即整体最优）
	LastResultIP6  string `json:"last_result_ip6,omitempty"` // IPv6 地址族优选结果（仅 test_ipv6 开启时写入）
	LastResultTime string `json:"last_result_time,omitempty"`
}

var (
	cfgPath     = "config.json" // 默认配置文件路径，可通过环境变量 DSA_CONFIG 覆盖
	cfgPathOnce sync.Once
	global      *Config
	gmu         sync.Mutex
)

// resolveCfgPath 返回配置文件路径（首次调用时读取 DSA_CONFIG 环境变量）。
func resolveCfgPath() string {
	cfgPathOnce.Do(func() {
		if p := os.Getenv("DSA_CONFIG"); p != "" {
			cfgPath = p
		}
	})
	return cfgPath
}

// Default 返回一份带合理默认值的配置。
func Default() *Config {
	return &Config{
		IPFile:          "ip.txt",
		Port:            443,
		TestCount:       10,
		PingTimes:       4,
		Routines:        200,
		IntervalMinutes: 60,
		RunOnStart:      false, // 默认不自动跑，避免每次启动都全量测速
		CustomDomains:   []string{"openrouter.ai"},
		TestIPv6:        true,
	}
}

// Load 从磁盘加载配置；文件不存在时返回默认配置。
func Load() (*Config, error) {
	c := Default()
	data, err := os.ReadFile(resolveCfgPath())
	if err != nil {
		if os.IsNotExist(err) {
			return c, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(data, c); err != nil {
		return nil, err
	}
	if c.CustomDomains == nil {
		c.CustomDomains = []string{}
	}
	if c.AdguardInstances == nil {
		c.AdguardInstances = []AdguardInstance{}
	}
	return c, nil
}

// Save 将当前配置写回磁盘（原子写入）。
func (c *Config) Save() error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(resolveCfgPath())
	tmp, err := os.CreateTemp(dir, ".cfs-config-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	// fsync 保证数据落盘后再 rename，极端断电场景不丢配置
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, resolveCfgPath()); err != nil {
		return err
	}
	// 同步目录项，确保 rename 本身也持久化
	if dirFile, err := os.Open(dir); err == nil {
		_ = dirFile.Sync()
		dirFile.Close()
	}
	return nil
}

// SetGlobal 设置全局单例（main 启动时调用一次）。
func SetGlobal(c *Config) {
	gmu.Lock()
	defer gmu.Unlock()
	global = c
}

// Global 获取全局单例。
func Global() *Config {
	gmu.Lock()
	defer gmu.Unlock()
	return global
}

// Clone 返回配置的深拷贝快照。
func (c *Config) Clone() Config {
	cp := *c
	cp.CustomDomains = append([]string(nil), c.CustomDomains...)
	cp.AdguardInstances = append([]AdguardInstance(nil), c.AdguardInstances...)
	for i := range cp.AdguardInstances {
		cp.AdguardInstances[i].ManualRewrites = append([]ManualRewrite(nil), cp.AdguardInstances[i].ManualRewrites...)
	}
	cp.DomainMetas = append([]DomainMeta(nil), c.DomainMetas...)
	return cp
}

// SyncDomainMeta 使 DomainMetas 与 CustomDomains 保持一致：
// 新增的域名补上 CreatedAt；被删除的域名移除元数据；已存在的保留原时间戳。
// now 由调用方传入以便测试。
func (c *Config) SyncDomainMeta(now time.Time) {
	nowStr := now.Format("2006-01-02 15:04:05")
	byName := make(map[string]DomainMeta, len(c.DomainMetas))
	for _, m := range c.DomainMetas {
		byName[m.Domain] = m
	}
	newMetas := make([]DomainMeta, 0, len(c.CustomDomains))
	for _, d := range c.CustomDomains {
		if m, ok := byName[d]; ok {
			m.UpdatedAt = nowStr // 已存在：仅刷新 UpdatedAt
			newMetas = append(newMetas, m)
		} else {
			// 新域名：Created 与 Updated 相同；迁移场景下保留旧行为
			newMetas = append(newMetas, DomainMeta{Domain: d, CreatedAt: nowStr, UpdatedAt: nowStr})
		}
	}
	c.DomainMetas = newMetas
}

// SetDomainWildcard 设置某域名的「包含子域」标志；无记录则新增元数据。
// 统一存储规范：CustomDomains 只存裸域名，通配状态始终记录在 DomainMetas。
func (c *Config) SetDomainWildcard(domain string, wildcard bool) {
	nowStr := time.Now().Format("2006-01-02 15:04:05")
	for i := range c.DomainMetas {
		if c.DomainMetas[i].Domain == domain {
			c.DomainMetas[i].Wildcard = wildcard
			c.DomainMetas[i].UpdatedAt = nowStr
			return
		}
	}
	c.DomainMetas = append(c.DomainMetas, DomainMeta{
		Domain:    domain,
		CreatedAt: nowStr,
		UpdatedAt: nowStr,
		Wildcard:  wildcard,
	})
}

const maskValue = "********"

// Sanitized 返回脱敏后的快照：所有 AdGuard 密码替换为掩码（用于 API 回显）。
func (c *Config) Sanitized() Config {
	cp := c.Clone()
	for i := range cp.AdguardInstances {
		if cp.AdguardInstances[i].Password != "" {
			cp.AdguardInstances[i].Password = maskValue
		}
	}
	return cp
}

// ApplyUpdateFields 仅应用请求中显式出现的字段（present[field]=true），
// 未提交的字段保留旧值。彻底解决「保存某个面板会把其他面板的开关/参数重置」
// 的问题（如保存测速参数时误关 IPv6 开关）。
func (c *Config) ApplyUpdateFields(in Config, present map[string]bool) {
	c.applyUpdate(in, present)
}

// applyUpdate 仅应用 present 中标记的字段。
func (c *Config) applyUpdate(in Config, present map[string]bool) {
	old := c.Clone()
	apply := func(field string) bool {
		return present[field]
	}

	if apply("adguard_instances") {
		// nil 表示本次提交未包含实例数据，保留旧值
		if in.AdguardInstances != nil {
			c.AdguardInstances = in.AdguardInstances
		}
		// 多实例密码处理：空 / 掩码 → 保留旧值；按 URL（及名称）匹配旧实例
		for i := range c.AdguardInstances {
			inst := &c.AdguardInstances[i]
			if inst.Password == "" || inst.Password == maskValue {
				inst.Password = old.findPassword(inst.Name, inst.URL)
			}
		}
	}
	if apply("ip_file") {
		c.IPFile = in.IPFile
		if c.IPFile == "" {
			c.IPFile = "ip.txt"
		}
	}
	if apply("port") {
		c.Port = in.Port
		if c.Port <= 0 {
			c.Port = 443
		}
	}
	if apply("httping") {
		c.Httping = in.Httping
	}
	if apply("cfcolo") {
		c.CFColo = in.CFColo
	}
	if apply("max_delay") {
		c.MaxDelay = in.MaxDelay
	}
	if apply("min_speed") {
		c.MinSpeed = in.MinSpeed
	}
	if apply("test_count") {
		c.TestCount = in.TestCount
		if c.TestCount <= 0 {
			c.TestCount = 10
		}
	}
	if apply("ping_times") {
		c.PingTimes = in.PingTimes
		if c.PingTimes <= 0 {
			c.PingTimes = 4
		}
	}
	if apply("routines") {
		c.Routines = in.Routines
		if c.Routines <= 0 {
			c.Routines = 200
		}
	}
	if apply("test_all") {
		c.TestAll = in.TestAll
	}
	if apply("disable_download") {
		c.DisableDownload = in.DisableDownload
	}
	if apply("test_url") {
		c.TestURL = in.TestURL
	}
	if apply("interval_minutes") {
		c.IntervalMinutes = in.IntervalMinutes
	}
	if apply("run_on_start") {
		c.RunOnStart = in.RunOnStart
	}
	if apply("test_ipv6") {
		c.TestIPv6 = in.TestIPv6
	}
	if apply("custom_domains") {
		// nil 表示本次提交未包含域名数据，保留旧值；显式 [] 表示清空
		if in.CustomDomains != nil {
			c.CustomDomains = in.CustomDomains
		}
	}
	if apply("domain_metas") {
		if in.DomainMetas != nil {
			c.DomainMetas = in.DomainMetas
		}
	}
	// 运行状态字段由内部管理，不接受外部提交，始终保留
	c.LastResultIP = old.LastResultIP
	c.LastResultIP6 = old.LastResultIP6
	c.LastResultTime = old.LastResultTime
}

// findPassword 按 url/name 查找旧实例的密码。
func (c *Config) findPassword(name, url string) string {
	for _, inst := range c.AdguardInstances {
		if inst.URL == url && (name == "" || inst.Name == name) {
			return inst.Password
		}
	}
	return ""
}
