import { useEffect, useRef, useState } from 'react';
import { api } from '../api';
import { toast } from '../Toast';
import ColoSelect from './ColoSelect';

const TRIGGER_NAMES = { manual: '手动', schedule: '定时', startup: '启动', watchdog: '守护' };

export default function SpeedtestPage() {
  const [cfg, setCfg] = useState({});
  const [history, setHistory] = useState([]);
  const [runModalIdx, setRunModalIdx] = useState(null);
  const [saveState, setSaveState] = useState('');

  const loadConfig = async () => {
    try {
      const c = await api('/api/config');
      setCfg(c);
    } catch (e) { toast(e.message, true); }
  };

  const loadHistory = async () => {
    try {
      const r = await api('/api/status');
      setHistory(r.history || []);
    } catch (e) { toast(e.message, true); }
  };

  useEffect(() => { loadConfig(); loadHistory(); }, []);

  // Escape 关闭任务详情弹窗
  useEffect(() => {
    const onKey = e => { if (e.key === 'Escape') setRunModalIdx(null); };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, []);

  const setField = (k, v) => setCfg(c => ({ ...c, [k]: v }));

  // 每次修改自动保存（500ms 防抖，单字段提交；失败时回滚为服务端状态）
  const timers = useRef({});
  const scheduleSave = (field, value) => {
    clearTimeout(timers.current[field]);
    timers.current[field] = setTimeout(async () => {
      try {
        await api('/api/config', { method: 'POST', body: JSON.stringify({ [field]: value }) });
        setSaveState('已保存 ✓');
        setTimeout(() => setSaveState(''), 2000);
      } catch (e) {
        toast('保存失败: ' + e.message, true);
        loadConfig();
      }
    }, 500);
  };

  // 文本/数字输入：本地即时更新，非空值防抖保存（空值视为未修改完成）
  const onInput = (field, numeric) => e => {
    const v = e.target.value;
    setField(field, v);
    if (v === '') return;
    scheduleSave(field, numeric ? Number(v) : v.trim());
  };

  // 开关：本地即时更新，防抖保存
  const onToggle = field => e => {
    setField(field, e.target.checked);
    scheduleSave(field, e.target.checked);
  };

  const runNow = async () => {
    try {
      const r = await api('/api/run', { method: 'POST' });
      toast(r.message || '已开始');
      setTimeout(loadHistory, 600);
    } catch (e) { toast(e.message, true); }
  };

  const interval = cfg.interval_minutes || 0;
  const h = runModalIdx !== null ? history[runModalIdx] : null;

  return (
    <div className="page active" id="page-speedtest">
      <div className="page-header">
        <h1>测速</h1>
        <p>获取最优 Cloudflare 节点 IP</p>
      </div>

      <div className="card">
        <h2>历史测速</h2>
        <div className="card-sub">最近 10 次测速任务</div>
        <table>
          <thead>
            <tr><th>时间</th><th>触发</th><th>最快 IP</th><th>延迟</th><th>速度</th><th>写入</th><th>耗时</th><th>状态</th></tr>
          </thead>
          <tbody>
            {history.length ? history.map((r, i) => (
              <tr className="clickable" key={i} onClick={() => setRunModalIdx(i)}>
                <td>{r.time}</td>
                <td><span className="badge">{TRIGGER_NAMES[r.trigger] || r.trigger}</span></td>
                <td className="mono">
                  {r.best_ip || '—'}
                  {r.best_ip6 && (
                    <div style={{ fontSize: 11, color: 'var(--text-tertiary)' }}>{r.best_ip6}</div>
                  )}
                </td>
                <td>{r.delay_ms ? r.delay_ms.toFixed(1) + ' ms' : '—'}</td>
                <td>{r.speed_mbps ? r.speed_mbps.toFixed(2) : '—'}</td>
                <td>{r.written || 0} 条</td>
                <td>{r.duration_s ? r.duration_s.toFixed(0) + 's' : '—'}</td>
                <td>
                  {r.ok
                    ? <span className="badge ok">成功</span>
                    : <span className="badge err" title={r.error || ''}>失败</span>}
                </td>
              </tr>
            )) : (
              <tr><td colSpan="8" className="t-empty">暂无任务记录</td></tr>
            )}
          </tbody>
        </table>
      </div>

      <div className="card">
        <h2>测速频率</h2>
        <div className="card-sub">自动执行测速任务的时间间隔</div>
        <div className="row2">
          <div>
            <label className="field-label">执行间隔（分钟，0 = 关闭自动测速）</label>
            <input type="number" min="0" value={cfg.interval_minutes ?? 60} onChange={onInput('interval_minutes', true)} />
          </div>
          <div>
            <label className="field-label">调度状态</label>
            <div style={{ paddingTop: 8 }}>
              {interval > 0
                ? <span className="badge ok">自动测速已启用 · 每 {interval} 分钟</span>
                : <span className="badge warn">自动测速已关闭</span>}
            </div>
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 16 }}>
          <label className="switch">
            <input type="checkbox" checked={!!cfg.run_on_start} onChange={onToggle('run_on_start')} />
            <span className="slider"></span>
          </label>
          <span style={{ fontSize: 13.5 }}>容器启动时立即开始测速</span>
        </div>
      </div>

      <div className="card">
        <h2>IPv6 测速（双栈优选）</h2>
        <div className="card-sub">
          启用后 IPv4 / IPv6 各自优选：文件型实例（dnsmasq/SmartDNS/MosDNS）同域名写入 A + AAAA 双记录；
          API 型实例（AdGuard/Technitium）同域名仅支持单条，固定写 IPv4 优选
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <label className="switch">
            <input type="checkbox" checked={cfg.test_ipv6 !== false} onChange={onToggle('test_ipv6')} />
            <span className="slider"></span>
          </label>
          <span style={{ fontSize: 13.5 }}>
            启用 IPv6<small style={{ color: 'var(--text-tertiary)', marginLeft: 8 }}>请确认网络环境是否支持 IPv6</small>
          </span>
        </div>
        <div className="hint">守护协程会分车道独立探测两个地址族并各自轮换备选；某地址族无可用结果时自动只写另一族。</div>
      </div>

      <div className="card">
        <h2>测速参数</h2>
        <div className="row3">
          <div><label className="field-label">测速端口</label><input type="number" value={cfg.port ?? 443} onChange={onInput('port', true)} /></div>
          <div><label className="field-label">下载测速数量</label><input type="number" value={cfg.test_count ?? 10} onChange={onInput('test_count', true)} /></div>
          <div><label className="field-label">IP 段文件</label><input type="text" value={cfg.ip_file || 'ip.txt'} onChange={onInput('ip_file', false)} /></div>
        </div>
        <div className="row2">
          <div><label className="field-label">延迟上限 (ms，0 = 不过滤)</label><input type="number" value={cfg.max_delay ?? 0} onChange={onInput('max_delay', true)} /></div>
          <div><label className="field-label">速度下限 (MB/s，0 = 不过滤)</label><input type="number" step="0.5" value={cfg.min_speed ?? 0} onChange={onInput('min_speed', true)} /></div>
        </div>
        <div className="hint">设置速度下限后，为找齐满足条件的 IP 可能对全部候选 IP 逐个下载测速，单轮耗时可能显著变长。</div>
        <div className="row2">
          <div><label className="field-label">测速地址（HTTPing / 下载测速共用，留空 = 默认）</label><input type="text" placeholder="https://cf.xiu2.xyz/url" value={cfg.test_url || ''} onChange={onInput('test_url', false)} /></div>
        </div>
        <div className="row2">
          <div>
            <label className="field-label">Cloudflare 节点区域（HTTPing 模式生效，留空 = 全部地区）</label>
            <ColoSelect
              value={cfg.cfcolo || ''}
              onChange={v => { setField('cfcolo', v); scheduleSave('cfcolo', v); }}
            />
          </div>
        </div>
        <div className="checkline">
          <label>
            <span className="switch"><input type="checkbox" checked={!!cfg.httping} onChange={onToggle('httping')} /><span className="slider"></span></span>
            HTTPing 模式
          </label>
          <label>
            <span className="switch"><input type="checkbox" checked={!!cfg.test_all} onChange={onToggle('test_all')} /><span className="slider"></span></span>
            测速全部 IP（有上限保护）
          </label>
          <label>
            <span className="switch"><input type="checkbox" checked={!!cfg.disable_download} onChange={onToggle('disable_download')} /><span className="slider"></span></span>
            禁用下载测速
          </label>
        </div>
        {cfg.test_all && (
          <div className="hint">⚠ 测速全部 IP 在大网段下耗时可能极长（10 万 IP × 200 并发 × 4 次 TCPing 最坏可达小时级），期间会占满出站连接，请谨慎开启。</div>
        )}
        <div className="actions">
          <button className="btn-ghost" onClick={runNow}>立即测速</button>
          <span style={{ fontSize: 12.5, color: 'var(--text-secondary)' }}>{saveState}</span>
        </div>
      </div>

      {h && (
        <div className="modal-scrim show" onClick={e => { if (e.target === e.currentTarget) setRunModalIdx(null); }}>
          <div className="modal">
            <button className="modal-close" onClick={() => setRunModalIdx(null)}>✕</button>
            <h3>任务详情 · {h.time}</h3>
            <div className="modal-sub">
              {(TRIGGER_NAMES[h.trigger] || h.trigger) + '触发 · ' +
                (h.ok
                  ? ('最快 IPv4 ' + (h.best_ip || '—') + ' · ' + (h.delay_ms ? h.delay_ms.toFixed(1) + ' ms' : '—') +
                    ' · ' + (h.speed_mbps ? h.speed_mbps.toFixed(2) + ' MB/s' : '—') + (h.colo ? ' · ' + h.colo : '') +
                    (h.best_ip6 ? ' · 最快 IPv6 ' + h.best_ip6 : '') +
                    ' · 写入 ' + (h.written || 0) + ' 条 · 耗时 ' + (h.duration_s ? h.duration_s.toFixed(0) + 's' : '—'))
                  : ('失败：' + (h.error || '未知错误')))}
            </div>
            <table>
              <thead><tr><th>#</th><th>IP 地址</th><th>延迟(ms)</th><th>速度(MB/s)</th><th>丢包率</th><th>地区码</th></tr></thead>
              <tbody>
                {(h.results || []).length
                  ? (h.results || []).map((r, j) => (
                    <tr key={j}>
                      <td>{j + 1}</td>
                      <td className="mono">{r.ip}</td>
                      <td>{r.delay_ms.toFixed(1)}</td>
                      <td>{r.speed_mbps.toFixed(2)}</td>
                      <td>{(r.loss_rate * 100).toFixed(0)}%</td>
                      <td>{r.colo || '—'}</td>
                    </tr>
                  ))
                  : <tr><td colSpan="6" className="t-empty">该任务无结果数据</td></tr>}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
