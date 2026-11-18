package dns

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/neon9809/cf-dns-select/config"
)

// ErrUnknownProvider 未知实例类型。
var ErrUnknownProvider = errors.New("未知的 DNS 实例类型")

// 文件型 provider 的规则文件格式。
const (
	fileFormatHosts       = "hosts"        // dnsmasq hostsdir / addn-hosts 格式
	fileFormatSmartDNS    = "smartdns"     // smartdns conf-file 格式（address /domain/ip）
	fileFormatMosDNSHosts = "mosdns_hosts" // mosdns hosts 插件外部文件格式（domain ip）
)

// 受管文件头注释：标识本文件由本工具生成，请勿手工编辑。
const managedFileHeader = "# 由 cf-dns-select 自动生成与接管，请勿手工编辑\n# 最后更新: %s\n"

// fileClient 文件型 DNS（dnsmasq / SmartDNS / MosDNS）的 Provider 实现。
//
// 调研结论：这三者均无运行时记录 CRUD API，管理方式为「受管规则文件 +
// reload/重启（dnsmasq hostsdir 可自动热读入）」。因此：
//   - ListRewrites：解析受管文件内容（只报告本工具管理的条目）；
//   - ReplaceRewrites：整文件重写 + 执行可选的 ReloadCmd；
//   - TestConnection：校验受管文件所在目录可写。
type fileClient struct {
	format    string // fileFormat* 常量
	name      string // provider 标识
	rulesFile string // 受管规则文件绝对路径
	reloadCmd string // 写入后执行的加载命令（可选）
}

// NewFileBased 创建文件型 provider。
func NewFileBased(inst config.AdguardInstance, name, format string) Provider {
	return &fileClient{
		format:    format,
		name:      name,
		rulesFile: inst.RulesFile,
		reloadCmd: inst.ReloadCmd,
	}
}

func (c *fileClient) Name() string { return c.name }

func (c *fileClient) TestConnection() error {
	if c.rulesFile == "" {
		return fmt.Errorf("未配置受管规则文件路径（rules_file）")
	}
	dir := filepath.Dir(c.rulesFile)
	fi, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("规则目录不可访问 %q: %w", dir, err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%q 不是目录", dir)
	}
	f, err := os.OpenFile(c.rulesFile, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("规则文件不可写 %q: %w", c.rulesFile, err)
	}
	return f.Close()
}

func (c *fileClient) ListRewrites() ([]RewriteEntry, error) {
	data, err := os.ReadFile(c.rulesFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []RewriteEntry{}, nil
		}
		return nil, err
	}
	out := make([]RewriteEntry, 0)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		switch c.format {
		case fileFormatHosts:
			// "1.2.3.4 domain"（系统 hosts 顺序）
			if len(fields) >= 2 {
				out = append(out, RewriteEntry{Domain: fields[1], Answer: fields[0], Enabled: true})
			}
		case fileFormatSmartDNS:
			// "address /domain/ip"（address 与规则体之间有空格）
			if len(fields) >= 2 && fields[0] == "address" && strings.HasPrefix(fields[1], "/") {
				body := strings.TrimSuffix(strings.TrimPrefix(fields[1], "/"), "/")
				if i := strings.LastIndex(body, "/"); i > 0 {
					out = append(out, RewriteEntry{Domain: body[:i], Answer: body[i+1:], Enabled: true})
				}
			}
		case fileFormatMosDNSHosts:
			// "domain ip"（mosdns hosts：域名在前 IP 在后）
			if len(fields) >= 2 {
				out = append(out, RewriteEntry{Domain: fields[0], Answer: fields[1], Enabled: true})
			}
		}
	}
	return out, nil
}

// render 按目标产品格式渲染期望集合。
func (c *fileClient) render(want map[string]map[string]bool) string {
	type pair struct{ domain, answer string }
	var pairs []pair
	for d, answers := range want {
		list := make([]string, 0, len(answers))
		for a := range answers {
			list = append(list, a)
		}
		sort.Strings(list)
		for _, a := range list {
			pairs = append(pairs, pair{d, a})
		}
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].domain < pairs[j].domain })

	var b strings.Builder
	fmt.Fprintf(&b, managedFileHeader, time.Now().Format("2006-01-02 15:04:05"))
	for _, p := range pairs {
		switch c.format {
		case fileFormatHosts:
			fmt.Fprintf(&b, "%s %s\n", p.answer, p.domain)
		case fileFormatSmartDNS:
			fmt.Fprintf(&b, "address /%s/%s\n", p.domain, p.answer)
		case fileFormatMosDNSHosts:
			fmt.Fprintf(&b, "%s %s\n", p.domain, p.answer)
		}
	}
	return b.String()
}

func (c *fileClient) ReplaceRewrites(want map[string]map[string]bool) (SyncStats, error) {
	var stats SyncStats

	old, err := c.ListRewrites()
	if err != nil {
		return stats, err
	}
	newCount := 0
	for _, answers := range want {
		newCount += len(answers)
	}

	content := c.render(want)
	if err := os.WriteFile(c.rulesFile, []byte(content), 0o644); err != nil {
		return stats, fmt.Errorf("写入受管规则文件失败 %q: %w", c.rulesFile, err)
	}
	stats.Written = newCount
	stats.Removed = len(old)

	// 执行可选的加载命令（如重启 smartdns/mosdns；dnsmasq hostsdir 无需此步）
	if cmd := strings.TrimSpace(c.reloadCmd); cmd != "" {
		if out, err := exec.Command("/bin/sh", "-c", cmd).CombinedOutput(); err != nil {
			return stats, fmt.Errorf("加载命令执行失败 (%s): %v: %s", cmd, err, strings.TrimSpace(string(out)))
		}
	}
	return stats, nil
}
