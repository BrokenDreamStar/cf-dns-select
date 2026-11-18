// Package speedtest 将 CloudflareSpeedTest 的测速逻辑封装为可编程调用的库，
// 供 dashboard 的定时任务 / 手动触发按钮使用。
//
// 注意：上游代码通过包级全局变量（task.* / utils.*）驱动测速，
// 因此本包【非并发安全】——同一进程内同一时刻只允许一个 Run() 在执行。
// web.Server 通过 running 标志保证这一点；如需新增并发入口请自行加包级互斥。
package speedtest

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/neon9809/cf-dns-select/task"
	"github.com/neon9809/cf-dns-select/utils"
)

// runMu 保证同一时刻只有一个测速在执行（保护上游全局变量）。
var runMu sync.Mutex

// onProgress 当次 Run 的进度回调（runMu 保护下串行使用）。
var onProgress ProgressFunc

// makeProgress 把上游阶段标识转为带中文描述的结构化进度。
func makeProgress(phase, detail string, current, total int) Progress {
	labels := map[string]string{
		"loading":  "加载 IP 段",
		"ping":     "延迟测速中",
		"download": "下载测速中",
		"writing":  "写入 AdGuard 重写规则",
		"done":     "完成",
	}
	return Progress{
		Phase:      phase,
		PhaseLabel: labels[phase],
		Current:    current,
		Total:      total,
		Detail:     detail,
	}
}

// Options 一次测速的全部参数。
type Options struct {
	IPFile          string
	Port            int
	Httping         bool
	CFColo          string
	MaxDelayMs      int     // 平均延迟上限（ms），<=0 不过滤
	MinSpeedMBps    float64 // 下载速度下限（MB/s），<=0 不过滤
	TestCount       int
	PingTimes       int
	Routines        int
	TestAll         bool
	DisableDownload bool
	URL             string // 测速地址（httping/下载测速用），空则使用默认
}

// Progress 描述一次测速的实时进度。
type Progress struct {
	Phase      string `json:"phase"`            // 阶段：loading / ping / download / writing / done
	PhaseLabel string `json:"phase_label"`      // 阶段的中文描述
	Current    int    `json:"current"`          // 已完成数量
	Total      int    `json:"total"`            // 总数量
	Detail     string `json:"detail,omitempty"` // 当前正在处理的地址等细节
}

// ProgressFunc 进度回调。并发调用方需自行保证安全。
type ProgressFunc func(Progress)

// Result 单个 IP 的测速结果。
type Result struct {
	IP        string  `json:"ip"`
	DelayMs   float64 `json:"delay_ms"`
	LossRate  float32 `json:"loss_rate"`
	SpeedMBps float64 `json:"speed_mbps"`
	Colo      string  `json:"colo,omitempty"`
	Sent      int     `json:"sent"`
	Received  int     `json:"received"`
}

// Run 执行一次完整测速，返回按最快排序的结果列表。
// onProgress 可为 nil；非 nil 时接收实时进度（阶段、当前正在测试的地址等）。
func Run(opt Options, onProgress ProgressFunc) ([]Result, error) {
	runMu.Lock()
	defer runMu.Unlock()

	// 将参数写入原项目的全局变量（原项目即以全局变量驱动）
	task.TCPPort = opt.Port
	if task.TCPPort <= 0 || task.TCPPort >= 65535 {
		task.TCPPort = 443
	}
	task.PingTimes = opt.PingTimes
	if task.PingTimes <= 0 {
		task.PingTimes = 4
	}
	task.Routines = opt.Routines
	if task.Routines <= 0 {
		task.Routines = 200
	}
	task.Httping = opt.Httping
	task.HttpingCFColo = opt.CFColo
	task.HttpingCFColomap = task.MapColoMap()
	task.IPFile = opt.IPFile
	if task.IPFile == "" {
		task.IPFile = "ip.txt"
	}
	// 地区库初始化（首次加载）；配置地区过滤时确保库路径就绪
	task.InitColoIPDB()
	defer func() {
		if err := task.ColoIPDB.Save(); err != nil {
			fmt.Printf("[警告] 地区库保存失败: %v\n", err)
		}
	}()
	task.TestAll = opt.TestAll
	task.Disable = opt.DisableDownload
	task.TestCount = opt.TestCount
	if task.TestCount <= 0 {
		task.TestCount = 10
	}
	task.MinSpeed = opt.MinSpeedMBps
	task.URL = opt.URL
	if task.URL == "" { // P2-8：未配置自定义测速地址时回退默认，避免复用上一轮的残留 URL
		task.URL = task.DefaultURL
	}

	if opt.MaxDelayMs > 0 {
		utils.InputMaxDelay = time.Duration(opt.MaxDelayMs) * time.Millisecond
	} else {
		utils.InputMaxDelay = 9999 * time.Millisecond // 默认值即不过滤
	}
	utils.InputMinDelay = 0
	utils.InputMaxLossRate = 1.0

	// 注册进度钩子：把上游进度条事件转成结构化 Progress 推给调用方
	if onProgress != nil {
		defer func() { utils.ProgressHook = nil }()
		utils.ProgressHook = func(phase, detail string, current, total int) {
			onProgress(makeProgress(phase, detail, current, total))
		}
	}

	pingData, err := task.NewPing()
	if err != nil {
		return nil, err
	}
	speedData := task.TestDownloadSpeed(pingData.Run().FilterDelay().FilterLossRate())

	results := make([]Result, 0, len(speedData))
	for _, v := range speedData {
		lossRate := float32(0)
		if v.Sended > 0 {
			lossRate = float32(v.Sended-v.Received) / float32(v.Sended)
		}
		results = append(results, Result{
			IP:        v.IP.String(),
			DelayMs:   v.Delay.Seconds() * 1000, // 保留亚毫秒精度
			LossRate:  lossRate,
			SpeedMBps: v.DownloadSpeed / 1024 / 1024,
			Colo:      v.Colo,
			Sent:      v.Sended,
			Received:  v.Received,
		})
	}
	if len(results) == 0 {
		return nil, fmt.Errorf("测速结果为 0 个可用 IP")
	}
	return results, nil
}

// Best 返回排序后的第一个结果。
//
// 选择策略说明（有意设计，非遗漏）：
//   - 结果列表已由上游按「丢包率 → 平均延迟」排序（禁用下载测速时），
//     或按「下载速度」排序（启用下载测速时）；
//   - 本函数直接取排序后的第一名，【不】对 IPv4/IPv6 做任何偏好——
//     混合双栈环境下哪个协议族的结果排第一就选哪个；
//   - 如需强制 IPv4/IPv6，可通过 ip.txt 换用对应协议族的 IP 段文件实现。
func Best(results []Result) (Result, bool) {
	if len(results) == 0 {
		return Result{}, false
	}
	return results[0], true
}

// IsIPv6 判断地址是否为 IPv6（IPv4-mapped 形式按 IPv4 计）。
func IsIPv6(ip string) bool {
	p := net.ParseIP(ip)
	return p != nil && p.To4() == nil
}

// BestOfFamily 返回结果列表中指定地址族的排名最高项
// （调用方传入的结果需已按排名排序，如 Run 的返回值或合并排序后的列表）。
func BestOfFamily(results []Result, ipv6 bool) (Result, bool) {
	for _, r := range results {
		if IsIPv6(r.IP) == ipv6 {
			return r, true
		}
	}
	return Result{}, false
}
