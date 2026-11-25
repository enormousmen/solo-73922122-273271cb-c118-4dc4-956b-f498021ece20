/* 交换机重载台前端逻辑：原生 JS，无外部依赖 */
(function () {
  "use strict";

  var $ = function (id) { return document.getElementById(id); };

  var EVENT_LABELS = {
    race_start: "竞速开始",
    start_path: "启动连接",
    tcp_connected: "TCP 已连接（每次均新建）",
    cert_verified: "证书校验通过",
    full_handshake: "完整握手（CA + 设备名校验）",
    session_resume_attempted: "携带缓存会话尝试恢复",
    session_resumed: "会话恢复成功（ abbreviated handshake ）",
    session_resume_declined_full_handshake: "服务端未接受恢复 → 同连接完整握手",
    session_save_skipped_stale_generation: "旧握手晚到，会话写入被世代守卫拒绝",
    ipv6_passed_within_window: "IPv6 在 250ms 窗口内通过",
    ipv6_early_failure_detected: "检测到 IPv6 提前失败",
    parallel_window_elapsed: "250ms 窗口到点，IPv6 尚未通过",
    winner_selected: "成为胜出路径，发送唯一 POST",
    other_path_released: "另一路连接已释放",
    loser_released: "落败连接已释放（未发送）",
    post_started: "开始发送 POST",
    post_sent: "POST 字节已全部发出",
    receipt_received: "收到完整设备回执",
    receipt_failed: "回执缺失/连接中断 → 结果未知",
    attempt_failed: "该路径尝试失败",
    attempt_canceled: "该路径被协调方主动取消（不影响已缓存会话）",
    post_connection_error: "发送后连接错误",
    deadline_reached: "到达 3 秒总时限",
    both_paths_failed_early: "两路均提前失败",
    finalized: "本次操作结束"
  };

  var MODE_EXPLAIN = {
    ipv6: {
      ok: "正常情况下本机回环 TLS 握手只需几十毫秒，IPv6 会在 250ms 内通过并直接胜出，不启动 IPv4。",
      stall: "演示：IPv6 的 TCP 能连上，但 TLS 握手一直卡住；250ms 后值班台并行尝试 IPv4，由 IPv4 完成下发。",
      reset: "演示：IPv6 被设备快速拒绝（RST），值班台检测到提前失败后立即尝试 IPv4，不等 250ms。"
    },
    ipv4: {
      ok: "IPv4 作为并行备份路径，正常时可随时接管。",
      stall: "演示：IPv4 握手也卡住。若与 IPv6 故障叠加，3 秒内无法开始 POST，结果为“未下发”。",
      reset: "演示：IPv4 快速失败。若 IPv6 也未在时限内通过，则判定“未下发”。"
    }
  };

  var HANDSHAKE_LABELS = {
    full: "完整握手",
    resumed: "会话恢复"
  };

  function api(url, options) {
    return fetch(url, Object.assign({
      headers: { "Content-Type": "application/json" }
    }, options || {})).then(function (r) {
      return r.json().then(function (data) {
        if (!r.ok) { throw new Error(data.error || ("HTTP " + r.status)); }
        return data;
      });
    });
  }

  function stackPill(stack) {
    if (!stack) return "";
    return '<span class="pill pill-' + stack + '">' + stack.toUpperCase() + "</span>";
  }

  function escapeHtml(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  function fmtClock(epoch) {
    return new Date(epoch * 1000).toISOString().substring(11, 19);
  }

  /* ---------------- 设备状态 / 计数 / 历史 / 会话面板 ---------------- */

  var controlsHydrated = false;
  function hydrateControlsOnce(state) {
    if (controlsHydrated || !state.settings) return;
    ["ipv6", "ipv4"].forEach(function (st) {
      var mode = state.settings[st + "_mode"];
      if (mode) {
        var radio = document.querySelector('input[name="' + st + '_mode"][value="' + mode + '"]');
        if (radio) radio.checked = true;
      }
    });
    $("disconnect").checked = !!state.settings.disconnect_after_execute;
    $("tls12-demo").checked = !!state.settings.tls12_demo;
    $("reject-ipv6").checked = !!state.settings.ipv6_reject_resume;
    $("reject-ipv4").checked = !!state.settings.ipv4_reject_resume;
    syncExplain();
    controlsHydrated = true;
  }

  function renderSessions(sessions) {
    ["ipv6", "ipv4"].forEach(function (st) {
      var info = sessions ? sessions[st] : null;
      var stateEl = $("session-state-" + st);
      var metaEl = $("session-meta-" + st);
      var box = $("session-box-" + st);
      box.classList.toggle("has-session", !!(info && info.present));
      if (!info || !info.present) {
        stateEl.textContent = "无缓存会话";
        stateEl.className = "session-state session-empty";
        var reason = info && info.reason && info.reason !== "none" ? info.reason : "";
        metaEl.innerHTML = '<li class="empty">暂无已保存会话' +
          (reason ? '（' + escapeHtml(reason) + '）' : '') + "</li>";
        return;
      }
      stateEl.textContent = HANDSHAKE_LABELS[info.handshake_kind] || info.handshake_kind;
      stateEl.className = "session-state session-" + info.handshake_kind;
      var rows = [
        ["TLS 版本", info.tls_version],
        ["密码套件", info.cipher],
        ["会话票据", info.has_ticket ? "有" : "无"],
        ["票寿命(s)", info.session_timeout_s],
        ["缓存年龄(s)", info.age_s],
        ["证书剩余(s)", info.cert_remaining_s],
        ["保存时刻(UTC)", fmtClock(info.saved_at)],
        ["世代号", info.generation]
      ];
      metaEl.innerHTML = rows.map(function (kv) {
        return "<li><span>" + escapeHtml(kv[0]) + "</span><code>" + escapeHtml(kv[1]) + "</code></li>";
      }).join("");
    });
  }

  function handshakeCell(h) {
    if (h.handshake_kind === "resumed") {
      return '<span class="pill pill-resumed">会话恢复</span>';
    }
    if (h.handshake_kind === "full") {
      return '<span class="pill pill-full">完整握手</span>' +
        (h.tls_version ? ' <code class="tls-ver">' + escapeHtml(h.tls_version) + "</code>" : "");
    }
    return '<span class="pill">默认协商</span>';
  }

  function renderState(state) {
    hydrateControlsOnce(state);
    $("count-total").textContent = state.reload_count;
    $("count-v6").textContent = state.stack_count.ipv6;
    $("count-v4").textContent = state.stack_count.ipv4;
    $("uptime").textContent = state.uptime_s + " s";

    var rows = $("history-body");
    if (!state.history.length) {
      rows.innerHTML = '<tr><td colspan="6" class="empty">暂无重载记录</td></tr>';
    } else {
      rows.innerHTML = state.history.map(function (h) {
        var t = new Date(h.time * 1000).toISOString().substring(11, 19);
        return "<tr>" +
          "<td class='mono'>#" + h.seq + "</td>" +
          "<td class='mono'>" + t + "</td>" +
          "<td>" + stackPill(h.stack) + "</td>" +
          "<td class='mono'>" + escapeHtml(h.request_id) + "</td>" +
          "<td>" + handshakeCell(h) + "</td>" +
          "<td>" + (h.disconnect
            ? '<span class="pill pill-disconnect">执行后断连</span>'
            : '<span class="pill pill-normal">完整回执</span>') + "</td>" +
          "</tr>";
      }).join("");
    }

    renderSessions(state.sessions);

    // 健康点
    $("health-dot").className = "dot dot-ok";
  }

  function refreshState() {
    return api("/api/state").then(renderState).catch(function () {
      $("health-dot").className = "dot dot-bad";
    });
  }

  /* ---------------- 演示设置 ---------------- */

  function currentSettings() {
    return {
      ipv6_mode: document.querySelector('input[name="ipv6_mode"]:checked').value,
      ipv4_mode: document.querySelector('input[name="ipv4_mode"]:checked').value,
      disconnect_after_execute: $("disconnect").checked,
      tls12_demo: $("tls12-demo").checked,
      ipv6_reject_resume: $("reject-ipv6").checked,
      ipv4_reject_resume: $("reject-ipv4").checked
    };
  }

  function syncExplain() {
    ["ipv6", "ipv4"].forEach(function (st) {
      var mode = document.querySelector('input[name="' + st + '_mode"]:checked').value;
      $("explain-" + st).textContent = MODE_EXPLAIN[st][mode] || "";
    });
  }

  var saveTimer = null;
  function saveSettings() {
    syncExplain();
    var tip = $("settings-saved");
    return api("/api/settings", { method: "POST", body: JSON.stringify(currentSettings()) })
      .then(function (data) {
        tip.textContent = "已应用 ✓";
        clearTimeout(saveTimer);
        saveTimer = setTimeout(function () { tip.textContent = ""; }, 1600);
        renderState(data.state);
      })
      .catch(function (err) { tip.textContent = "设置失败：" + err.message; });
  }

  document.querySelectorAll('input[name="ipv6_mode"], input[name="ipv4_mode"]').forEach(function (el) {
    el.addEventListener("change", saveSettings);
  });
  $("disconnect").addEventListener("change", saveSettings);
  $("tls12-demo").addEventListener("change", saveSettings);
  $("reject-ipv6").addEventListener("change", saveSettings);
  $("reject-ipv4").addEventListener("change", saveSettings);

  var SCENARIOS = {
    normal:      { ipv6_mode: "ok",    ipv4_mode: "ok",    disconnect_after_execute: false },
    v6stall:     { ipv6_mode: "stall", ipv4_mode: "ok",    disconnect_after_execute: false },
    v6reset:     { ipv6_mode: "reset", ipv4_mode: "ok",    disconnect_after_execute: false },
    disconnect:  { ipv6_mode: "ok",    ipv4_mode: "ok",    disconnect_after_execute: true  },
    neither:     { ipv6_mode: "stall", ipv4_mode: "stall", disconnect_after_execute: false }
  };

  document.querySelectorAll(".btn-ghost[data-scenario]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var sc = SCENARIOS[btn.getAttribute("data-scenario")];
      if (!sc) return;
      document.querySelector('input[name="ipv6_mode"][value="' + sc.ipv6_mode + '"]').checked = true;
      document.querySelector('input[name="ipv4_mode"][value="' + sc.ipv4_mode + '"]').checked = true;
      $("disconnect").checked = sc.disconnect_after_execute;
      saveSettings();
    });
  });

  $("btn-reset-count").addEventListener("click", function () {
    api("/api/reset-count", { method: "POST" }).then(function (d) { renderState(d.state); });
  });

  /* ---------------- 忘记会话 ---------------- */

  document.querySelectorAll(".btn-forget").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var stack = btn.getAttribute("data-forget");
      api("/api/session/forget", {
        method: "POST",
        body: JSON.stringify({ stack: stack })
      }).then(function (d) {
        renderState(d.state);
        appendDemoLog("已让样例设备忘记 " + stack.toUpperCase() + " 入口的会话（在途握手世代同时作废）");
      });
    });
  });

  /* ---------------- TLS 演示序列 ---------------- */

  var demoLogEl = $("tls-demo-log");
  function appendDemoLog(msg, cls) {
    demoLogEl.classList.remove("hidden");
    var line = document.createElement("div");
    line.className = "demo-log-line " + (cls || "");
    var ts = new Date().toISOString().substring(11, 19);
    line.textContent = "[" + ts + "] " + msg;
    demoLogEl.insertBefore(line, demoLogEl.firstChild);
  }

  function wait(ms) { return new Promise(function (res) { setTimeout(res, ms); }); }

  function ensureTls12() {
    $("tls12-demo").checked = true;
    $("reject-ipv6").checked = false;
    $("reject-ipv4").checked = false;
    return saveSettings().then(function () { return wait(150); });
  }

  function doReloadStep(label) {
    return api("/api/reload", { method: "POST", body: "{}" }).then(function (payload) {
      var r = payload.result;
      var kind = r.winner_handshake_kind ? (HANDSHAKE_LABELS[r.winner_handshake_kind] || r.winner_handshake_kind) : "–";
      appendDemoLog(
        label + " → status=" + r.status +
        " winner=" + (r.winner || "无") +
        " 握手=" + kind +
        (r.attempts[r.winner] && r.attempts[r.winner].tls_version
          ? " 版本=" + r.attempts[r.winner].tls_version : ""),
        r.winner_handshake_kind === "resumed" ? "log-resumed"
          : r.winner_handshake_kind === "full" ? "log-full" : ""
      );
      renderResult(payload);
      renderState(payload.device);
      return payload;
    });
  }

  var tlsScenarioRunning = false;
  var TLS_SCENARIOS = {
    "same-stack": function () {
      return ensureTls12()
        .then(function () { return api("/api/session/forget", { method: "POST", body: JSON.stringify({ stack: "both" }) }); })
        .then(function () { return wait(100); })
        .then(function () { return doReloadStep("①-第1次（IPv6，预期完整握手）"); })
        .then(function () { return wait(300); })
        .then(function () { return doReloadStep("①-第2次（IPv6，预期会话恢复）"); });
    },
    "switch-stack": function () {
      return ensureTls12()
        .then(function () { return api("/api/session/forget", { method: "POST", body: JSON.stringify({ stack: "both" }) }); })
        .then(function () { return wait(100); })
        // 先制造一份 IPv6 会话
        .then(function () { return doReloadStep("②-第1次 IPv6（完整握手）"); })
        .then(function () {
          // 让 IPv6 卡住 250ms 后并行 IPv4，由 IPv4 完整握手
          document.querySelector('input[name="ipv6_mode"][value="stall"]').checked = true;
          document.querySelector('input[name="ipv4_mode"][value="ok"]').checked = true;
          return saveSettings();
        })
        .then(function () { return wait(150); })
        .then(function () { return doReloadStep("②-第2次 IPv6 卡住 → IPv4（完整握手）"); })
        .then(function () {
          document.querySelector('input[name="ipv6_mode"][value="ok"]').checked = true;
          return saveSettings();
        })
        .then(function () { return wait(150); })
        .then(function () { return doReloadStep("②-第3次 恢复 IPv6（预期 IPv6 会话恢复）"); });
    },
    "forget": function () {
      return ensureTls12()
        .then(function () { return doReloadStep("③-第1次（建立会话）"); })
        .then(function () { return api("/api/session/forget", { method: "POST", body: JSON.stringify({ stack: "both" }) }); })
        .then(function () {
          appendDemoLog("③ 已忘记两栈会话");
          return wait(200);
        })
        .then(function () { return doReloadStep("③-第2次（预期重新完整握手）"); })
        .then(function () { return wait(300); })
        .then(function () { return doReloadStep("③-第3次（再次预期会话恢复）"); });
    },
    "reject": function () {
      return ensureTls12()
        .then(function () { return doReloadStep("④-第1次（建立 IPv6 会话）"); })
        .then(function () {
          $("reject-ipv6").checked = true;
          return saveSettings();
        })
        .then(function () { return wait(200); })
        .then(function () { return doReloadStep("④-第2次（IPv6 拒绝恢复 → 同连接完整握手）"); })
        .then(function () {
          $("reject-ipv6").checked = false;
          return saveSettings();
        })
        .then(function () { return wait(200); })
        .then(function () { return doReloadStep("④-第3次（关闭拒绝后重新完整握手、签新票据）"); })
        .then(function () { return wait(300); })
        .then(function () { return doReloadStep("④-第4次（同栈再次重载 → 会话恢复）"); });
    }
  };

  document.querySelectorAll(".btn-ghost[data-tls-scenario]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      if (tlsScenarioRunning) return;
      var fn = TLS_SCENARIOS[btn.getAttribute("data-tls-scenario")];
      if (!fn) return;
      tlsScenarioRunning = true;
      btn.classList.add("scenario-busy");
      Promise.resolve()
        .then(fn)
        .catch(function (err) { appendDemoLog("演示序列失败：" + err.message, "log-err"); })
        .then(function () {
          tlsScenarioRunning = false;
          btn.classList.remove("scenario-busy");
          refreshState();
        });
    });
  });

  /* ---------------- 重载与结果渲染 ---------------- */

  function kindForEvent(ev) {
    if (ev === "cert_verified" || ev === "receipt_received" || ev === "winner_selected" ||
        ev === "session_resumed") return "ok";
    if (ev === "attempt_failed" || ev === "receipt_failed") return "bad";
    if (ev === "deadline_reached" || ev === "parallel_window_elapsed" ||
        ev === "ipv6_early_failure_detected" || ev === "both_paths_failed_early" ||
        ev === "session_resume_declined_full_handshake") return "warn";
    return "";
  }

  function renderTimeline(events) {
    var wrap = $("timeline-wrap");
    wrap.classList.remove("hidden");
    $("timeline").innerHTML = events.map(function (e) {
      var label = EVENT_LABELS[e.event] || e.event;
      var detailParts = [];
      ["reason", "error", "http_status", "handshake_ms", "cn", "bytes", "connect_ms",
       "generation", "handshake_kind", "session_saved"].forEach(function (k) {
        if (e[k] !== undefined && e[k] !== null) {
          var v = typeof e[k] === "string" && e[k].length > 120 ? e[k].slice(0, 120) + "…" : e[k];
          detailParts.push(k + "=" + v);
        }
      });
      if (e.detail && typeof e.detail === "object") {
        // race_start 的大对象不展开
      }
      return "<li class='kind-" + kindForEvent(e.event) + "'>" +
        "<span class='t'>+" + e.t_ms + "ms</span>" +
        (e.stack ? "<span class='st st-" + e.stack + "'>" + e.stack + "</span>"
                 : "<span class='st st-system'>sys</span>") +
        "<span class='ev'>" + escapeHtml(label) + "</span>" +
        (detailParts.length ? "<span class='detail'>" + escapeHtml(detailParts.join(" · ")) + "</span>" : "") +
        "</li>";
    }).join("");
  }

  function renderResult(payload) {
    var r = payload.result;
    var banner = $("result-banner");
    banner.classList.remove("hidden", "running", "delivered", "not_sent", "unknown");
    banner.classList.add(r.status);

    var icon = r.status === "delivered" ? "✓" : (r.status === "unknown" ? "⚠" : "✕");
    var sub = "";
    if (r.status === "delivered" && r.receipt) {
      sub = "设备 " + escapeHtml(r.receipt.body.device) +
            " 经 " + (r.winner || "").toUpperCase() +
            " 完成执行，共用计数现为 #" + r.receipt.body.reload_count;
    } else if (r.status === "unknown") {
      sub = "POST 已开始发送，但未收到完整回执；不会换路重发。可在下方计数/历史中确认设备是否已执行。";
    } else {
      sub = "3 秒结束前没有任何一路开始发送 POST，未下发到设备。";
    }
    banner.innerHTML = "<span style='font-size:22px'>" + icon + "</span>" +
      "<div>" + escapeHtml(r.status_text) +
      "<span class='sub'>" + sub + "</span></div>";

    $("winner-row").classList.remove("hidden");
    var w = $("winner");
    w.textContent = r.winner ? r.winner.toUpperCase() + "（同一设备名校验通过）" : "无";
    w.className = r.winner ? "winner-" + r.winner : "";

    var kindEl = $("handshake-kind");
    kindEl.textContent = r.winner_handshake_kind
      ? (HANDSHAKE_LABELS[r.winner_handshake_kind] || r.winner_handshake_kind)
      : "–";
    kindEl.className = r.winner_handshake_kind === "resumed" ? "hs-resumed"
      : r.winner_handshake_kind === "full" ? "hs-full" : "";

    var winnerAttempt = r.winner ? r.attempts[r.winner] : null;
    $("tls-version").textContent = winnerAttempt && winnerAttempt.tls_version
      ? winnerAttempt.tls_version : "–";
    $("elapsed").textContent = r.elapsed_ms;
    $("post-started").textContent = r.post_started ? "是" : "否";

    if (r.receipt) {
      $("receipt-wrap").classList.remove("hidden");
      $("receipt").textContent = JSON.stringify(r.receipt.body, null, 2);
    } else {
      $("receipt-wrap").classList.add("hidden");
    }
    if (r.error) {
      $("error-wrap").classList.remove("hidden");
      var lines = [r.error, "", "各路径明细："];
      Object.keys(r.attempts).forEach(function (st) {
        var a = r.attempts[st];
        lines.push("[" + st + "] cert_passed=" + a.cert_passed +
          " failed=" + a.failed + (a.error ? " error=" + a.error : "") +
          (a.cert ? " cn=" + a.cert.subject_cn + " verified_against=" + a.cert.verified_against_name : "") +
          (a.handshake_kind ? " handshake=" + a.handshake_kind : ""));
      });
      $("error-text").textContent = lines.join("\n");
    } else {
      $("error-wrap").classList.add("hidden");
    }

    renderTimeline(r.timeline);
    renderState(payload.device);
  }

  var running = false;
  $("btn-reload").addEventListener("click", function () {
    if (running) return;
    running = true;
    var btn = $("btn-reload");
    btn.disabled = true;
    btn.classList.add("loading");
    btn.querySelector(".btn-text").textContent = "竞速下发中（最长 3 秒）…";

    var banner = $("result-banner");
    banner.classList.remove("hidden", "delivered", "not_sent", "unknown");
    banner.classList.add("running");
    banner.textContent = "正在双栈竞速：先 IPv6，" + window.APP_CONFIG.parallelDelayMs +
      "ms 未过证书校验则并行 IPv4 …";

    api("/api/reload", { method: "POST", body: "{}" })
      .then(renderResult)
      .catch(function (err) {
        banner.classList.remove("running");
        banner.classList.add("unknown");
        banner.textContent = "请求控制台失败：" + err.message;
      })
      .finally(function () {
        running = false;
        btn.disabled = false;
        btn.classList.remove("loading");
        btn.querySelector(".btn-text").textContent = "重载交换机配置";
        refreshState();
      });
  });

  /* ---------------- 启动 ---------------- */
  syncExplain();
  refreshState();
  setInterval(refreshState, 2500);
})();
