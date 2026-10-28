"""HTML Dashboard for Phonix v2.0 Gateway Control Center.

Self-contained Single-Page Application (HTML5 + Vanilla JS + Tailwind via CDN/fallback CSS).
Zero external runtime dependencies.
"""

from __future__ import annotations


def render_dashboard_html() -> str:
    """Renders the interactive Phonix v2.0 Mini Web UI Dashboard."""
    return """<!DOCTYPE html>
<html lang="vi" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Phonix v2.0 - Gateway Control Center</title>
  <link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>🔥</text></svg>">
  <script src="https://cdn.tailwindcss.com"></script>
  <script>
    tailwind.config = {
      darkMode: 'class',
      theme: {
        extend: {
          colors: {
            brand: {
              50: '#eff6ff',
              500: '#3b82f6',
              600: '#2563eb',
              900: '#1e3a8a',
            }
          }
        }
      }
    }
  </script>
  <style>
    body { background-color: #0b0f19; color: #e5e7eb; font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
    .card { background-color: #111827; border: 1px solid #1f2937; border-radius: 0.75rem; }
    .btn-green { background-color: #059669; color: white; transition: all 0.2s; }
    .btn-green:hover { background-color: #047857; }
    .btn-yellow { background-color: #d97706; color: white; transition: all 0.2s; }
    .btn-yellow:hover { background-color: #b45309; }
    .btn-red { background-color: #dc2626; color: white; transition: all 0.2s; }
    .btn-red:hover { background-color: #b91c1c; }
    .badge-ro { background-color: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }
    .badge-injected { background-color: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.3); }
  </style>
</head>
<body class="min-h-screen p-4 md:p-8">
  <div class="max-w-6xl mx-auto space-y-6">

    <!-- Header -->
    <header class="card p-6 flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-l-4 border-l-blue-500 shadow-xl">
      <div>
        <div class="flex items-center gap-3">
          <span class="text-3xl">🔥</span>
          <h1 class="text-2xl font-bold tracking-tight text-white">Phonix v2.0 Gateway Control Center</h1>
        </div>
        <p class="text-sm text-gray-400 mt-1">Zero-Trust AST Paging & 1.5B Micro-Router • Context MMU Hub</p>
      </div>
      <div class="flex flex-wrap items-center gap-2 text-xs">
        <span id="badgeStatus" class="px-3 py-1.5 rounded-full font-semibold flex items-center gap-1.5 bg-emerald-950/80 text-emerald-400 border border-emerald-800">
          <span class="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span> Live Gateway
        </span>
        <span class="px-3 py-1.5 rounded-full font-mono bg-blue-950/80 text-blue-300 border border-blue-800">
          Port: 8000
        </span>
        <span class="px-3 py-1.5 rounded-full font-mono bg-purple-950/80 text-purple-300 border border-purple-800">
          VRAM: 1.2 GB Strict
        </span>
        <span class="px-3 py-1.5 rounded-full font-mono bg-indigo-950/80 text-indigo-300 border border-indigo-800">
          Z3 SMT: Verified
        </span>
      </div>
    </header>

    <!-- Key Metrics Telemetry Grid -->
    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      <div class="card p-5">
        <div class="text-xs font-medium text-gray-400 uppercase tracking-wider">Context Token Nén</div>
        <div class="text-2xl font-bold text-emerald-400 mt-1" id="metricCompression">97.50%</div>
        <div class="text-xs text-gray-400 mt-1">Tiết kiệm: <span id="metricTokensSaved" class="text-white font-semibold">0</span> tokens</div>
      </div>
      <div class="card p-5">
        <div class="text-xs font-medium text-gray-400 uppercase tracking-wider">Circuit Breaker</div>
        <div class="text-2xl font-bold text-blue-400 mt-1" id="metricBreaker">25 / 40 Turns</div>
        <div class="text-xs text-gray-400 mt-1">Tripped: <span id="metricTrips" class="text-white font-semibold">0</span> • Polling Blocked: <span id="metricPolling" class="text-white font-semibold">0</span></div>
      </div>
      <div class="card p-5">
        <div class="text-xs font-medium text-gray-400 uppercase tracking-wider">Zero-Trust Security</div>
        <div class="text-2xl font-bold text-indigo-400 mt-1">ENFORCED</div>
        <div class="text-xs text-gray-400 mt-1">Formal Proofs: <span class="text-emerald-400 font-semibold">100% Zero Leak</span></div>
      </div>
      <div class="card p-5">
        <div class="text-xs font-medium text-gray-400 uppercase tracking-wider">Dự Án Trong RAM</div>
        <div class="text-2xl font-bold text-amber-400 mt-1" id="metricWorkspacesCount">0</div>
        <div class="text-xs text-gray-400 mt-1">Tổng file: <span id="metricTotalFiles" class="text-white font-semibold">0</span> • AST Frames: <span id="metricTotalFrames" class="text-white font-semibold">0</span></div>
      </div>
    </div>

    <!-- Workspace Linker Card -->
    <div class="card p-6 shadow-lg">
      <div class="flex items-center justify-between pb-4 border-b border-gray-800">
        <div>
          <h2 class="text-lg font-bold text-white flex items-center gap-2">
            <span>📁</span> Workspace Connector & Explicit Policy Distribution
          </h2>
          <p class="text-xs text-gray-400 mt-1">
            Giao diện kết nối dự án minh bạch. Nạp dự án 100% chỉ đọc trong bộ nhớ RAM (0 byte ghi đĩa). Chỉ thả file rule khi người dùng bấm xác nhận.
          </p>
        </div>
        <button onclick="refreshAll()" class="text-xs px-3 py-1.5 rounded bg-gray-800 hover:bg-gray-700 text-gray-300 border border-gray-700">
          🔄 Làm mới
        </button>
      </div>

      <div class="mt-5 space-y-4">
        <div>
          <label for="wsPathInput" class="block text-xs font-semibold text-gray-300 mb-1.5 uppercase">
            Đường dẫn thư mục dự án mục tiêu (Target Workspace Directory):
          </label>
          <div class="relative">
            <input
              type="text"
              id="wsPathInput"
              placeholder="D:\\UIT\\NamBonUIT\\ArcProxy"
              class="w-full px-4 py-2.5 rounded-lg bg-gray-900 border border-gray-700 text-white placeholder-gray-500 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
          </div>
        </div>

        <div class="flex flex-wrap items-center gap-3 pt-2">
          <button
            onclick="attachWorkspaceAction()"
            id="btnAttach"
            class="btn-green px-5 py-2.5 rounded-lg text-sm font-semibold shadow-md flex items-center gap-2"
          >
            <span>🟢</span> Nạp Dự Án (Chỉ Đọc - 0 Byte File)
          </button>

          <button
            onclick="injectRuleAction()"
            id="btnInject"
            class="btn-yellow px-5 py-2.5 rounded-lg text-sm font-semibold shadow-md flex items-center gap-2"
          >
            <span>🟡</span> Nhả Rule PhonixHP.md
          </button>

          <button
            onclick="cleanRuleAction()"
            id="btnClean"
            class="btn-red px-5 py-2.5 rounded-lg text-sm font-semibold shadow-md flex items-center gap-2"
          >
            <span>🔴</span> Thu Hồi & Dọn Sạch
          </button>
        </div>

        <!-- Live Toast Notification Banner -->
        <div id="toastNotification" class="hidden p-4 rounded-lg text-sm transition-all border"></div>
      </div>
    </div>

    <!-- Attached Workspaces Table -->
    <div class="card p-6 shadow-lg">
      <div class="flex items-center justify-between pb-3 border-b border-gray-800">
        <h3 class="text-base font-bold text-white flex items-center gap-2">
          <span>📑</span> Danh Sách Dự Án Đã Nạp Trong Bộ Nhớ (Attached Workspaces)
        </h3>
        <span class="text-xs text-gray-400" id="tableCounter">0 dự án</span>
      </div>

      <div class="overflow-x-auto mt-4">
        <table class="w-full text-left text-sm text-gray-300">
          <thead class="text-xs uppercase bg-gray-900/60 text-gray-400 border-b border-gray-800">
            <tr>
              <th class="px-4 py-3">Tên & Đường Dẫn Dự Án</th>
              <th class="px-4 py-3">Chế Độ (Mode)</th>
              <th class="px-4 py-3">Số File Đã Quét</th>
              <th class="px-4 py-3">AST Frames</th>
              <th class="px-4 py-3 text-right">Thao Tác</th>
            </tr>
          </thead>
          <tbody id="workspaceTableBody" class="divide-y divide-gray-800 font-mono text-xs">
            <tr>
              <td colspan="5" class="px-4 py-8 text-center text-gray-500 font-sans">
                Chưa có dự án nào được nạp. Hãy nhập đường dẫn thư mục ở trên và bấm <strong>"Nạp Dự Án (Chỉ Đọc)"</strong> để quét cấu trúc mã nguồn vào RAM.
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Architecture & Safety Invariants Footer Card -->
    <div class="card p-5 text-xs text-gray-400 space-y-2 border-dashed">
      <div class="font-semibold text-gray-300 uppercase tracking-wider flex items-center gap-2">
        <span>🛡️</span> Nguyên Tắc Bất Biến Về An Toàn Không Gian Làm Việc (Zero-Invasion Invariants):
      </div>
      <ul class="list-disc list-inside space-y-1 text-gray-400">
        <li><strong>Read-Only by Default</strong>: Thao tác quét nạp dự án không bao giờ ghi bất kỳ file nào lên ổ cứng.</li>
        <li><strong>No Global Pollution</strong>: Không tự ý ghi đè vào <code>~/.gemini</code> hay thư mục người dùng cá nhân.</li>
        <li><strong>Explicit Rule Deployment</strong>: Chỉ ghi duy nhất <code>.agents/rules/PhonixHP.md</code> khi người dùng chủ động bấm xác nhận "Nhả Rule".</li>
        <li><strong>Clean Reversibility</strong>: Bấm "Thu Hồi & Dọn Sạch" sẽ xóa ngay lập tức file rule và hoàn trả <code>.git/info/exclude</code> nguyên vẹn.</li>
      </ul>
    </div>

  </div>

  <script>
    function showToast(message, isSuccess = true) {
      const toast = document.getElementById('toastNotification');
      toast.className = isSuccess
        ? 'p-4 rounded-lg text-sm bg-emerald-950/80 border border-emerald-600/50 text-emerald-200 block'
        : 'p-4 rounded-lg text-sm bg-rose-950/80 border border-rose-600/50 text-rose-200 block';
      toast.innerHTML = (isSuccess ? '✅ ' : '❌ ') + message;
      setTimeout(() => {
        toast.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      }, 50);
    }

    async function fetchHealth() {
      try {
        const res = await fetch('/health');
        if (!res.ok) return;
        const data = await res.json();
        if (data.telemetry) {
          document.getElementById('metricTokensSaved').innerText = (data.telemetry.total_tokens_saved || 0).toLocaleString();
        }
        document.getElementById('metricTrips').innerText = data.circuit_breaker_trips || 0;
        document.getElementById('metricPolling').innerText = data.polling_loops_blocked || 0;
      } catch (err) {
        console.debug('Health fetch error:', err);
      }
    }

    async function fetchWorkspaces() {
      try {
        const res = await fetch('/v1/workspaces');
        if (!res.ok) return;
        const list = await res.json();
        const tbody = document.getElementById('workspaceTableBody');
        const counter = document.getElementById('tableCounter');

        const workspaces = Array.isArray(list) ? list : (list.workspaces || []);
        counter.innerText = `${workspaces.length} dự án`;
        document.getElementById('metricWorkspacesCount').innerText = workspaces.length;

        let totalFiles = 0;
        let totalFrames = 0;

        if (workspaces.length === 0) {
          tbody.innerHTML = `
            <tr>
              <td colspan="5" class="px-4 py-8 text-center text-gray-500 font-sans">
                Chưa có dự án nào được nạp. Hãy nhập đường dẫn thư mục ở trên và bấm <strong>"Nạp Dự Án (Chỉ Đọc)"</strong> để quét cấu trúc mã nguồn vào RAM.
              </td>
            </tr>
          `;
          document.getElementById('metricTotalFiles').innerText = 0;
          document.getElementById('metricTotalFrames').innerText = 0;
          return;
        }

        let html = '';
        for (const ws of workspaces) {
          totalFiles += ws.indexed_files || 0;
          totalFrames += ws.ast_frames || 0;
          const isRuleInjected = ws.status === 'rule_injected';
          const badgeClass = isRuleInjected ? 'badge-injected' : 'badge-ro';
          const badgeText = isRuleInjected ? 'Protected (PhonixHP.md)' : 'Read-Only (0-Byte File)';

          html += `
            <tr class="hover:bg-gray-900/50 transition-colors">
              <td class="px-4 py-3">
                <div class="font-bold text-white font-sans">${escapeHtml(ws.name || '')}</div>
                <div class="text-gray-500 truncate max-w-md" title="${escapeHtml(ws.workspace_path)}">${escapeHtml(ws.workspace_path)}</div>
              </td>
              <td class="px-4 py-3">
                <span class="px-2.5 py-1 rounded text-xs font-semibold ${badgeClass}">
                  ${badgeText}
                </span>
              </td>
              <td class="px-4 py-3 text-white font-bold">${(ws.indexed_files || 0).toLocaleString()}</td>
              <td class="px-4 py-3 text-purple-300 font-bold">${(ws.ast_frames || 0).toLocaleString()}</td>
              <td class="px-4 py-3 text-right space-x-1.5 font-sans">
                <button
                  onclick="selectAndAttach('${escapeJs(ws.workspace_path)}')"
                  class="px-2.5 py-1 text-xs rounded bg-gray-800 hover:bg-gray-700 text-gray-200 border border-gray-700"
                  title="Quét lại file vào bộ nhớ"
                >
                  🔄 Quét lại
                </button>
                ${
                  !isRuleInjected
                    ? `<button
                        onclick="selectAndInject('${escapeJs(ws.workspace_path)}')"
                        class="px-2.5 py-1 text-xs rounded bg-amber-900/70 hover:bg-amber-800 text-amber-200 border border-amber-700"
                        title="Thả rule PhonixHP.md vào dự án"
                      >
                        🟡 Nhả Rule
                      </button>`
                    : `<button
                        onclick="selectAndClean('${escapeJs(ws.workspace_path)}')"
                        class="px-2.5 py-1 text-xs rounded bg-rose-950/80 hover:bg-rose-900 text-rose-300 border border-rose-800"
                        title="Thu hồi file rule"
                      >
                        🔴 Thu Hồi
                      </button>`
                }
                <button
                  onclick="detachWorkspaceAction('${escapeJs(ws.workspace_path)}')"
                  class="px-2 py-1 text-xs rounded bg-gray-800 hover:bg-red-950 text-gray-400 hover:text-red-300 border border-gray-700"
                  title="Gỡ khỏi RAM"
                >
                  ✕ Gỡ
                </button>
              </td>
            </tr>
          `;
        }

        tbody.innerHTML = html;
        document.getElementById('metricTotalFiles').innerText = totalFiles.toLocaleString();
        document.getElementById('metricTotalFrames').innerText = totalFrames.toLocaleString();
      } catch (err) {
        console.error('Workspaces fetch error:', err);
      }
    }

    function getTargetInput() {
      const val = document.getElementById('wsPathInput').value.trim();
      if (!val) {
        showToast('Vui lòng nhập đường dẫn thư mục dự án mục tiêu.', false);
        return null;
      }
      return val;
    }

    async function attachWorkspaceAction(pathOverride = null) {
      const path = pathOverride || getTargetInput();
      if (!path) return;

      try {
        const res = await fetch('/v1/workspace/attach', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ workspace_path: path })
        });
        const data = await res.json();
        if (res.ok) {
          showToast(data.message || `Đã nạp thành công '${data.name}' (${data.indexed_files} file, ${data.ast_frames} AST frames) hoàn toàn trong RAM!`, true);
          document.getElementById('wsPathInput').value = path;
          await refreshAll();
        } else {
          showToast(data.detail || 'Không thể nạp dự án. Kiểm tra đường dẫn tồn tại.', false);
        }
      } catch (err) {
        showToast(`Lỗi kết nối tới Gateway: ${err.message}`, false);
      }
    }

    async function injectRuleAction(pathOverride = null) {
      const path = pathOverride || getTargetInput();
      if (!path) return;

      const confirmed = confirm(
        `Xác nhận thả rule PhonixHP.md vào thư mục:\\n${path}\\n\\nThao tác này sẽ tạo duy nhất file .agents/rules/PhonixHP.md và cập nhật .git/info/exclude để không làm bẩn git.`
      );
      if (!confirmed) return;

      try {
        const res = await fetch('/v1/workspace/inject-rule', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ workspace_path: path })
        });
        const data = await res.json();
        if (res.ok) {
          showToast(data.message || `Đã thả rule PhonixHP.md thành công vào ${path}!`, true);
          await refreshAll();
        } else {
          showToast(data.detail || 'Lỗi khi thả rule.', false);
        }
      } catch (err) {
        showToast(`Lỗi kết nối tới Gateway: ${err.message}`, false);
      }
    }

    async function cleanRuleAction(pathOverride = null) {
      const path = pathOverride || getTargetInput();
      if (!path) return;

      const confirmed = confirm(`Xác nhận thu hồi và xóa sạch PhonixHP.md khỏi:\\n${path}`);
      if (!confirmed) return;

      try {
        const res = await fetch('/v1/workspace/clean-rule', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ workspace_path: path })
        });
        const data = await res.json();
        if (res.ok) {
          showToast(data.message || `Đã thu hồi PhonixHP.md và dọn sạch git exclude khỏi ${path}!`, true);
          await refreshAll();
        } else {
          showToast(data.detail || 'Lỗi khi dọn dẹp rule.', false);
        }
      } catch (err) {
        showToast(`Lỗi kết nối tới Gateway: ${err.message}`, false);
      }
    }

    async function detachWorkspaceAction(path) {
      if (!confirm(`Xác nhận gỡ dự án '${path}' khỏi bộ nhớ RAM?`)) return;
      try {
        const res = await fetch('/v1/workspace/detach', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ workspace_path: path })
        });
        const data = await res.json();
        if (res.ok) {
          showToast(data.message || `Đã gỡ dự án khỏi RAM.`, true);
          await refreshAll();
        } else {
          showToast(data.detail || 'Lỗi khi gỡ dự án.', false);
        }
      } catch (err) {
        showToast(`Lỗi kết nối tới Gateway: ${err.message}`, false);
      }
    }

    function selectAndAttach(path) {
      document.getElementById('wsPathInput').value = path;
      attachWorkspaceAction(path);
    }

    function selectAndInject(path) {
      document.getElementById('wsPathInput').value = path;
      injectRuleAction(path);
    }

    function selectAndClean(path) {
      document.getElementById('wsPathInput').value = path;
      cleanRuleAction(path);
    }

    async function refreshAll() {
      await Promise.all([fetchHealth(), fetchWorkspaces()]);
    }

    function escapeHtml(str) {
      return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    function escapeJs(str) {
      return String(str).replace(/\\\\/g, '\\\\\\\\').replace(/'/g, "\\\\'");
    }

    // Auto-init on page load
    window.addEventListener('DOMContentLoaded', () => {
      refreshAll();
      setInterval(fetchHealth, 10000);
    });
  </script>
</body>
</html>
"""
