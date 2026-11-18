import { useEffect, useRef, useState } from 'react';
import { api, getToken } from '../api';
import { toast } from '../Toast';
import { appAlert, appChoice, appConfirm } from '../AppModal';

const PROVIDER_TYPES = [
  { value: 'adguard', label: 'AdGuard Home', api: true },
  { value: 'technitium', label: 'Technitium DNS', api: true },
  { value: 'dnsmasq', label: 'dnsmasq（hostsdir 文件）', api: false },
  { value: 'smartdns', label: 'SmartDNS（conf-file 文件）', api: false },
  { value: 'mosdns', label: 'MosDNS（hosts 规则文件）', api: false },
];

export default function InstancesPage() {
  const [instances, setInstances] = useState([]);
  const [form, setForm] = useState({ name: '', type: 'adguard', url: '', username: '', password: '', rules_file: '', reload_cmd: '' });
  const [tested, setTested] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testState, setTestState] = useState({ text: '', color: '' });
  const [pane, setPane] = useState('adguard');

  // 查看重写弹窗
  const [rwModal, setRwModal] = useState(null); // {url, list, filter, sub, loading}
  const syncPolling = useRef(new Set());
  const [syncing, setSyncing] = useState({}); // url -> true（触发重渲染用）

  const refreshInstances = async () => {
    try {
      const r = await api('/api/instances');
      setInstances(r.instances || []);
    } catch (e) { toast(e.message, true); }
  };

  useEffect(() => { refreshInstances(); }, []);

  useEffect(() => {
    const onKey = e => { if (e.key === 'Escape') setRwModal(null); };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, []);

  const resetInstanceTest = () => {
    setTested(false);
    setTestState({ text: '', color: '' });
  };

  const onFormInput = (k, v) => {
    setForm(f => ({ ...f, [k]: v }));
    resetInstanceTest();
  };

  const testInstanceInput = async () => {
    const isAPI = PROVIDER_TYPES.find(t => t.value === form.type)?.api;
    if (isAPI && !form.url.trim()) { toast('请先填写实例地址', true); return; }
    if (!isAPI && !form.rules_file.trim()) { toast('请先填写受管规则文件路径', true); return; }
    setTesting(true);
    setTestState({ text: '测试中...', color: '' });
    try {
      const t = await api('/api/test-instance', {
        method: 'POST',
        body: JSON.stringify({
          type: form.type,
          url: form.url.trim(),
          username: form.username.trim(),
          password: form.password,
          rules_file: form.rules_file.trim(),
          reload_cmd: form.reload_cmd,
        }),
      });
      if (t.ok) {
        setTested(true);
        setTestState({ text: '✓ 连接成功，可以添加', color: 'var(--ok)' });
      } else {
        setTested(false);
        setTestState({ text: '✗ ' + (t.error || '连接失败'), color: 'var(--err)' });
      }
    } catch (e) {
      setTested(false);
      setTestState({ text: '✗ ' + e.message, color: 'var(--err)' });
    } finally {
      setTesting(false);
    }
  };

  const addInstance = async (adopt = '') => {
    if (!tested && !adopt) { toast('请先通过测试连接', true); return; }
    const body = {
      name: form.name.trim(),
      type: form.type,
      url: form.url.trim(),
      username: form.username.trim(),
      password: form.password,
      rules_file: form.rules_file.trim(),
      reload_cmd: form.reload_cmd,
      adopt,
    };
    // API 型校验实例地址；文件型无地址字段，校验受管规则文件路径（URL 由后端按文件路径合成）
    const isAPI = PROVIDER_TYPES.find(t => t.value === form.type)?.api;
    if (isAPI && !body.url) { toast('请填写实例地址', true); return; }
    if (!isAPI && !body.rules_file) { toast('请填写受管规则文件路径', true); return; }
    try {
      const resp = await fetch('/api/instances', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + getToken() },
        body: JSON.stringify(body),
      });
      const data = await resp.json().catch(() => ({}));
      // 409：实例上已有重写规则，需二选一确认接管方式（关闭弹窗 = 放弃添加）
      if (resp.status === 409 && data.rewrites) {
        const list = data.rewrites || [];
        const lines = list.map(c => c.domain + '  →  ' + c.answer).join('\n');
        const choice = await appChoice(
          '接管该实例的整张重写表',
          '检测到该实例上已有 ' + list.length + ' 条重写规则。添加后本工具将清空整表并重新下发（测速最优 IP + 自定义重写）。现有规则如何处置？',
          lines,
          [
            { label: '保留到自定义重写', value: 'import', className: 'btn-primary' },
            { label: '抛弃现有规则', value: 'discard', className: 'btn-danger' },
          ]
        );
        if (!choice) return; // 关闭弹窗 = 放弃添加
        await addInstance(choice);
        return;
      }
      if (!resp.ok) { toast(data.error || ('HTTP ' + resp.status), true); return; }
      setForm({ name: '', type: form.type, url: '', username: '', password: '', rules_file: '', reload_cmd: '' });
      resetInstanceTest();
      toast(adopt === 'import'
        ? '实例已保存，现有规则已导入自定义重写表 ✓'
        : adopt === 'discard' ? '实例已保存，现有规则已抛弃 ✓' : '实例已保存 ✓');
      await refreshInstances();
    } catch (e) { toast(e.message, true); }
  };

  const deleteInstance = async url => {
    const ok = await appConfirm('删除实例', '确定删除实例 ' + url + ' ？');
    if (!ok) return;
    try {
      await api('/api/instances', { method: 'DELETE', body: JSON.stringify({ url }) });
      toast('实例已删除');
      await refreshInstances();
    } catch (e) { toast(e.message, true); }
  };

  const syncInstance = async url => {
    if (syncPolling.current.has(url)) { toast('该实例同步正在进行中...', true); return; }
    try {
      await api('/api/instances/sync?url=' + encodeURIComponent(url), { method: 'POST' });
    } catch (e) { toast(e.message, true); return; }
    toast('同步任务已启动，正在后台执行...');
    syncPolling.current.add(url);
    setSyncing(s => ({ ...s, [url]: true }));
    try {
      // 轮询直到任务完成（最长 10 分钟）
      for (let i = 0; i < 120; i++) {
        await new Promise(r => setTimeout(r, 5000));
        const st = await api('/api/instances/sync');
        if (!st.running) {
          for (const res of (st.results || [])) {
            if (res.error) {
              await appAlert('同步警告', res.name + ' 同步有警告', res.error, true);
            } else {
              toast(res.name + ' 同步完成：写入 ' + res.written + ' 条，清理过期 ' + res.removed + ' 条 ✓');
            }
          }
          break;
        }
      }
    } catch (e) { toast(e.message, true); }
    syncPolling.current.delete(url);
    setSyncing(s => ({ ...s, [url]: false }));
    refreshInstances();
  };

  const viewRewrites = async url => {
    setRwModal({ url, sub: url + ' · 加载中...', list: [], filter: '', manual: [], manualDomain: '', manualAnswer: '' });
    try {
      const r = await api('/api/rewrites?url=' + encodeURIComponent(url));
      setRwModal(m => m && ({ ...m, list: r.rewrites || [], sub: url + ' · 共 ' + (r.rewrites || []).length + ' 条规则' }));
    } catch (e) {
      setRwModal(m => m && ({ ...m, sub: url, error: e.message }));
    }
    // 该实例独有的手动重写表
    try {
      const r = await api('/api/manual-rewrites?url=' + encodeURIComponent(url));
      setRwModal(m => m && ({ ...m, manual: r.rewrites || [] }));
    } catch (e) { /* 静默 */ }
  };

  const addManualRewrite = async () => {
    const { url, manualDomain, manualAnswer } = rwModal;
    if (!manualDomain.trim() || !manualAnswer.trim()) { toast('请填写域名与解析目标', true); return; }
    try {
      const r = await api('/api/manual-rewrites?url=' + encodeURIComponent(url), {
        method: 'POST',
        body: JSON.stringify({ domain: manualDomain.trim(), answer: manualAnswer.trim() }),
      });
      setRwModal(m => m && ({ ...m, manual: r.rewrites || [], manualDomain: '', manualAnswer: '' }));
      toast('已添加，正在后台同步该实例 ✓');
      setTimeout(refreshInstances, 1500); // 等后台整表下发后刷新规则数/一致性
    } catch (e) { toast(e.message, true); }
  };

  const removeManualRewrite = async m => {
    try {
      const r = await api(
        '/api/manual-rewrites/' + encodeURIComponent(m.domain) + '?answer=' + encodeURIComponent(m.answer) +
        '&url=' + encodeURIComponent(rwModal.url),
        { method: 'DELETE' }
      );
      setRwModal(s => s && ({ ...s, manual: r.rewrites || [] }));
      toast('已删除，正在后台同步该实例 ✓');
      setTimeout(refreshInstances, 1500);
    } catch (e) { toast(e.message, true); }
  };

  const filteredRewrites = () => {
    if (!rwModal) return [];
    const f = rwModal.filter.toLowerCase();
    return rwModal.list.filter(x =>
      !f || x.domain.toLowerCase().includes(f) || x.answer.toLowerCase().includes(f));
  };

  return (
    <div className="page active" id="page-instances">
      <div className="page-header">
        <h1>实例</h1>
        <p>管理 DNS 重写目标实例</p>
      </div>

      <div className="seg">
        {PROVIDER_TYPES.map(t => (
          <button
            key={t.value}
            className={pane === t.value ? 'active' : ''}
            onClick={() => {
              setPane(t.value);
              setForm(f => ({ ...f, type: t.value }));
              resetInstanceTest();
            }}
          >
            {t.label.split('（')[0]}
          </button>
        ))}
      </div>

      <div className={'seg-pane' + (pane === form.type ? ' active' : '')}>
        <div className="card">
          <h2>添加 {PROVIDER_TYPES.find(t => t.value === pane)?.label} 实例</h2>
          <div className="card-sub">
            {PROVIDER_TYPES.find(t => t.value === pane)?.api
              ? 'API 型在线管理记录，变更动态生效'
              : '文件型：写入受管规则文件（需挂载到本容器）'}
          </div>
          <div className="row2">
            <div><label className="field-label">实例名称</label><input type="text" placeholder="如：主力 DNS 服务" value={form.name} onChange={e => onFormInput('name', e.target.value)} /></div>
            {PROVIDER_TYPES.find(t => t.value === pane)?.api && (
              <div><label className="field-label">地址</label><input type="text" placeholder="例如: http://192.168.1.2:3000" value={form.url} onChange={e => onFormInput('url', e.target.value)} /></div>
            )}
          </div>
          {PROVIDER_TYPES.find(t => t.value === pane)?.api ? (
            <>
              <div className="row2">
                {pane === 'adguard' && (
                  <div><label className="field-label">用户名</label><input type="text" autoComplete="off" placeholder="输入用户名" value={form.username} onChange={e => onFormInput('username', e.target.value)} /></div>
                )}
                <div><label className="field-label">{pane === 'technitium' ? 'API Token' : '密码'}</label><input type={pane === 'technitium' ? 'text' : 'password'} autoComplete="new-password" placeholder={pane === 'technitium' ? 'Technitium API Token' : '输入密码'} value={form.password} onChange={e => onFormInput('password', e.target.value)} /></div>
              </div>
            </>
          ) : (
            <>
              <div className="row2">
                <div><label className="field-label">受管规则文件路径（容器内绝对路径）</label><input type="text" placeholder="/etc/dnsmasq.d/cf-dns-select.hosts" value={form.rules_file} onChange={e => onFormInput('rules_file', e.target.value)} /></div>
                <div><label className="field-label">加载命令（可选，规则写入后执行）</label><input type="text" placeholder="如：systemctl restart smartdns" value={form.reload_cmd} onChange={e => onFormInput('reload_cmd', e.target.value)} /></div>
              </div>
              <div className="hint">请把该路径所在目录挂载进本容器（volumes）。dnsmasq 的 hostsdir 会自动热读入；SmartDNS/MosDNS 建议配置重启命令。</div>
            </>
          )}
          <div className="actions">
            <button className="btn-ghost" disabled={testing} onClick={testInstanceInput}>测试连接</button>
            <button className="btn-primary" disabled={!tested} onClick={() => addInstance()}>添加实例</button>
            <span style={{ fontSize: 12.5, color: testState.color || undefined }}>{testState.text}</span>
          </div>
        </div>

        <div className="card">
          <h2>已有实例</h2>
          <div className="card-sub">测试中最快响应的 Cloudflare 节点 IP 将写入以下实例的 DNS 重写表</div>
          {instances.filter(i => (i.type || 'adguard') === pane).length ? instances.filter(i => (i.type || 'adguard') === pane).map(inst => (
            <div className="inst-row" key={inst.url}>
              <span className="name">{inst.name}</span>
              <span className="url mono">{inst.url}</span>
              {inst.ok
                ? <span className="badge ok">在线 · {inst.rules} 条规则</span>
                : <span className="badge err" title={inst.error || ''}>离线</span>}
              {inst.ok && inst.sync === 'synced' && (
                <span className="badge ok" title="重写与期望一致">✓ 已是最新</span>
              )}
              {inst.ok && inst.sync === 'drift' && (
                <span className="badge warn" title={(inst.drift || []).join('\n')}>⚠ 有差异 ({(inst.drift || []).length})</span>
              )}
              {inst.ok && inst.sync === 'unknown' && (
                <span className="badge" title="尚无测速结果，无法比对">— 未知</span>
              )}
              <button className="btn-ghost btn-sm" onClick={() => viewRewrites(inst.url)}>查看重写</button>
              {inst.sync === 'drift' && (
                <button
                  className="btn-primary btn-sm"
                  disabled={!!syncing[inst.url]}
                  onClick={() => syncInstance(inst.url)}
                >
                  ⟳ 同步 ({(inst.drift || []).length})
                </button>
              )}
              <button className="btn-danger btn-sm" onClick={() => deleteInstance(inst.url)}>删除</button>
            </div>
          )) : (
            <span className="hint">尚未添加任何 {PROVIDER_TYPES.find(t => t.value === pane)?.label} 实例</span>
          )}

        </div>
      </div>

      {rwModal && (
        <div className="modal-scrim show" onClick={e => { if (e.target === e.currentTarget) setRwModal(null); }}>
          <div className="modal">
            <button className="modal-close" onClick={() => setRwModal(null)}>✕</button>
            <h3>重写规则</h3>
            <div className="modal-sub">{rwModal.sub}</div>
            <input
              type="text"
              placeholder="搜索域名或 IP…"
              style={{ marginBottom: 12 }}
              value={rwModal.filter}
              onChange={e => setRwModal(m => m && ({ ...m, filter: e.target.value }))}
            />
            <div className="rewrite-list">
              {rwModal.error ? (
                <div className="t-empty" style={{ color: 'var(--err)' }}>{rwModal.error}</div>
              ) : filteredRewrites().length ? filteredRewrites().map((x, i) => (
                <div className="rewrite-item" key={i}>
                  <span className="rd mono">{x.domain}</span>
                  <span style={{ color: 'var(--text-tertiary)' }}>→</span>
                  <span className="ra mono" style={{ color: 'var(--ok)' }}>{x.answer}</span>
                  {x.enabled === false && <span className="badge err">停用</span>}
                </div>
              )) : (
                <div className="t-empty">{rwModal.list.length ? '无匹配结果' : '暂无重写规则'}</div>
              )}
            </div>

            {/* 自定义重写（本实例独有）：非 Cloudflare 域名，同步时与最优 IP 一并整表下发 */}
            <div style={{ marginTop: 20, borderTop: '1px solid var(--separator)', paddingTop: 16 }}>
              <h3 style={{ fontSize: 16, letterSpacing: '-0.01em', marginBottom: 4 }}>自定义重写（仅本实例）</h3>
              <div className="modal-sub" style={{ marginBottom: 12 }}>
                手动维护的非 Cloudflare 重写规则；每次同步会与测速最优 IP 合并整表下发到该实例
              </div>
              <div style={{ display: 'flex', gap: 10 }}>
                <input
                  type="text"
                  placeholder="域名，如 nas.example.com"
                  style={{ flex: 1.2, marginBottom: 0 }}
                  value={rwModal.manualDomain || ''}
                  onChange={e => setRwModal(m => m && ({ ...m, manualDomain: e.target.value }))}
                  onKeyDown={e => { if (e.key === 'Enter') addManualRewrite(); }}
                />
                <input
                  type="text"
                  placeholder="解析目标，如 192.168.1.50"
                  style={{ flex: 1, marginBottom: 0 }}
                  value={rwModal.manualAnswer || ''}
                  onChange={e => setRwModal(m => m && ({ ...m, manualAnswer: e.target.value }))}
                  onKeyDown={e => { if (e.key === 'Enter') addManualRewrite(); }}
                />
                <button className="btn-primary" style={{ flexShrink: 0 }} onClick={addManualRewrite}>添加</button>
              </div>
              <div className="rewrite-list">
                {(rwModal.manual || []).length ? rwModal.manual.map((m, i) => (
                  <div className="rewrite-item" key={i}>
                    <span className="badge accent">手动</span>
                    <span className="rd mono">{m.domain}</span>
                    <span style={{ color: 'var(--text-tertiary)' }}>→</span>
                    <span className="ra mono" style={{ color: 'var(--ok)' }}>{m.answer}</span>
                    <button className="btn-danger btn-sm" onClick={() => removeManualRewrite(m)}>删除</button>
                  </div>
                )) : (
                  <div className="t-empty">暂无手动重写规则</div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
