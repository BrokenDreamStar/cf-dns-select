import { useCallback, useEffect, useState } from 'react';
import { api } from '../api';
import { toast } from '../Toast';

export default function StatusPage() {
  const [status, setStatus] = useState({});
  const [domains, setDomains] = useState([]);

  const load = useCallback(async () => {
    try {
      const r = await api('/api/status');
      setStatus(r.status || {});
    } catch (e) { /* 401 由 App 处理 */ }
  }, []);

  useEffect(() => { load(); }, [load]);

  // 测速进行中：1.5s 轮询
  useEffect(() => {
    if (!status.running) return undefined;
    const t = setTimeout(load, 1500);
    return () => clearTimeout(t);
  }, [status, load]);

  useEffect(() => {
    api('/api/domains/list').then(r => setDomains(r.domains || [])).catch(() => {});
  }, []);

  const runNow = async () => {
    try {
      const r = await api('/api/run', { method: 'POST' });
      toast(r.message || '已开始');
      setTimeout(load, 600);
    } catch (e) { toast(e.message, true); }
  };

  const results = status.results || [];
  const top3 = results.slice(0, 3);
  const running = !!status.running;
  const p = status.progress;

  // 状态页域名 chips（通配域名用绿色外框标识）
  const domainList = domains || [];

  return (
    <div className="page active" id="page-status">
      <div className="page-header">
        <h1>状态</h1>
      </div>

      <div className="card">
        <div className="card-sub">{status.last_run_time ? '测速时间: ' + status.last_run_time : '尚未测速'}</div>
        <div className="stat-row">
          {top3.length ? top3.map((r, i) => (
            <div className="stat" key={i}>
              <div className="label">#{i + 1} {i === 0 ? (r.ip.includes(':') ? '最快 IPv6' : '最快 IPv4') : '候选'}</div>
              <div className={'value mono' + (i === 0 ? ' ok' : '')}>{r.ip}</div>
              <div className="label" style={{ marginTop: 4 }}>
                {r.delay_ms.toFixed(1)} ms · {r.speed_mbps.toFixed(2)} MB/s{r.colo ? ' · ' + r.colo : ''}
              </div>
            </div>
          )) : (
            <div className="stat"><div className="label">最快 IP</div><div className="value mono">—</div></div>
          )}
          {status.best_ip6 && (
            <div className="stat">
              <div className="label">最快 IPv6</div>
              <div className="value mono ok">{status.best_ip6}</div>
              <div className="label" style={{ marginTop: 4 }}>
                {status.best_ip6_delay_ms ? status.best_ip6_delay_ms.toFixed(1) + ' ms' : '双栈优选'}
              </div>
            </div>
          )}
        </div>
        <div className="actions">
          <button className="btn-primary" disabled={running} onClick={runNow}>
            {running ? '正在测速' : '立即测速'}
          </button>
          <span style={{ color: 'var(--err)', fontSize: 12.5 }}>{status.last_error || ''}</span>
        </div>
        <div className={'progress-wrap' + (running ? ' show' : '')}>
          <div className="progress-track">
            <div
              className={'progress-fill' + (p && p.total > 0 ? '' : ' indeterminate')}
              style={p && p.total > 0 ? { width: Math.round(p.current / p.total * 100) + '%' } : undefined}
            />
          </div>
          <div className="progress-text">
            <span>{p ? (p.phase_label || p.phase) : '—'}</span>
            <span>
              {p && p.total > 0
                ? p.current + ' / ' + p.total + '（' + Math.round(p.current / p.total * 100) + '%）'
                : p && p.current > 0 ? p.current + ' 已完成' : '—'}
            </span>
          </div>
          <div className="progress-detail">{p && p.detail ? '正在测试：' + p.detail : ''}</div>
        </div>
      </div>

      <div className="card">
        <h2>已配置域名</h2>
        <div className="card-sub">以下域名由 Cloudflare 边缘节点提供服务，配置的 DNS 服务实例将为用户解析最快响应的 IP</div>
        {domainList.length ? (
          <div className="domains-wrap">
            {domainList.map(d => (
              <span
                key={d.domain}
                className={'domain-chip' + (d.wildcard ? ' wildcard' : '')}
              >
                {d.domain}
              </span>
            ))}
          </div>
        ) : (
          <span className="hint">尚未配置任何域名</span>
        )}
      </div>
    </div>
  );
}
