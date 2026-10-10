// Try a call: post the caller's line to /api/call and draw the stock and gated panes.
(function () {
  var form = document.getElementById('dial');
  var said = document.getElementById('said');
  var phone = document.getElementById('phone');
  var status = document.getElementById('status');
  var go = document.getElementById('go');
  var duel = document.getElementById('duel');
  var callerPhone = '+91-98123-45678';

  var rupees = function (n) { return '₹' + Number(n || 0).toLocaleString('en-IN'); };
  var el = function (tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  };

  form.querySelectorAll('.presets button').forEach(function (b) {
    b.addEventListener('click', function () {
      said.value = b.dataset.text;
      callerPhone = b.dataset.phone;
      phone.textContent = callerPhone;
      form.querySelectorAll('.presets button').forEach(function (o) { o.setAttribute('aria-pressed', o === b); });
      form.requestSubmit();
    });
  });
  said.addEventListener('input', function () {
    form.querySelectorAll('.presets button').forEach(function (o) { o.setAttribute('aria-pressed', 'false'); });
  });

  var STAMP = { ALLOW: 's-allow', NARROW: 's-narrow', BLOCK: 's-block', ESCALATE: 's-escalate' };
  var LABEL = { UNGUARDED: 'No gate' };

  function argText(args) {
    var keys = Object.keys(args || {});
    if (!keys.length) return '';
    return keys.map(function (k) {
      var v = args[k];
      return k + '=' + (k === 'amount_inr' ? rupees(v) : String(v));
    }).join('  ');
  }

  function stepRow(s, gated) {
    var li = el('li');
    var stamp = el('span', 'stamp ' + (STAMP[s.verb] || 's-none'), LABEL[s.verb] || s.verb);
    var body = el('div');
    var what = s.tool || (s.kind === 'task_open' ? 'task opened' : 'tool visibility');
    var head = el('p', 'step-tool');
    head.appendChild(el('code', null, what));
    if (s.agent) head.appendChild(el('span', 'step-agent', ' ' + s.agent));
    body.appendChild(head);
    var a = argText(s.args);
    if (a) body.appendChild(el('p', 'step-args', a));
    var reason = (s.reason || '').replace(/^\[local-simulation: [^\]]+\]\s*/, '');
    if (gated && (s.rule || reason)) {
      var why = el('p', 'step-why');
      if (s.rule) why.appendChild(el('code', null, s.rule));
      if (reason) why.appendChild(document.createTextNode(' ' + reason));
      body.appendChild(why);
      if (s.denial_step) body.appendChild(el('p', 'step-sim', 'Simulated: ' + s.denial_step.replace(/^local-simulation:\s*/, '')));
    } else if (!gated && s.reason && s.tool) {
      body.appendChild(el('p', 'step-why bad', s.reason));
    }
    li.appendChild(stamp);
    li.appendChild(body);
    return li;
  }

  function countUp(node, to) {
    var reduce = window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (!to || reduce) { node.textContent = rupees(to); return; }
    var t0 = null;
    var tick = function (t) {
      t0 = t0 || t;
      var k = Math.min(1, (t - t0) / 900);
      node.textContent = rupees(Math.round(to * (1 - Math.pow(1 - k, 3))));
      if (k < 1) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  }

  function draw(mode, pane) {
    var gated = mode === 'gated';
    var box = document.getElementById('pane-' + mode);
    box.querySelectorAll(':scope > :not(h2)').forEach(function (n) { n.remove(); });
    var moved = pane.moved_off_file_inr || 0;
    var fig = el('p', 'moved');
    fig.appendChild(el('span', 'moved-label', 'Moved to accounts not on file'));
    var num = el('span', 'moved-fig ' + (moved ? 'bad' : 'good'), rupees(0));
    fig.appendChild(num);
    box.appendChild(fig);
    countUp(num, moved);
    box.appendChild(el('blockquote', 'reply', pane.reply || pane.error || ''));
    var list = el('ol', 'steps');
    (pane.steps || []).forEach(function (s, i) {
      var row = stepRow(s, gated);
      row.style.setProperty('--d', (i * 0.12) + 's');
      list.appendChild(row);
    });
    box.appendChild(list);
    var foot = el('p', 'fine', (gated ? 'Decided by ' + pane.source + '. ' : 'No enforcement. ') + (pane.verified || ''));
    if (pane.record) {
      var a = el('a', null, 'Download the signed record');
      a.href = URL.createObjectURL(new Blob([pane.record], { type: 'application/x-ndjson' }));
      a.download = 'cleargate-' + mode + '.jsonl';
      foot.appendChild(document.createTextNode(' '));
      foot.appendChild(a);
    }
    box.appendChild(foot);
  }

  function render(body) {
    draw('stock', body.panes.stock);
    draw('gated', body.panes.gated);
    duel.hidden = false;
    duel.classList.remove('landed');
    void duel.offsetWidth;
    duel.classList.add('landed');
    status.textContent = 'Heard (' + body.language + '): "' + body.transcript + '"';
    duel.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
  // voice.js hands spoken calls to the same renderer.
  window.cleargateRender = render;

  form.addEventListener('submit', function (ev) {
    ev.preventDefault();
    var text = said.value.trim();
    if (!text) { said.focus(); return; }
    go.disabled = true;
    status.textContent = 'Calling the support line…';
    fetch('/api/call', { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text: text, phone: callerPhone }) })
      .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, body: j }; }); })
      .then(function (res) {
        if (!res.ok) throw new Error(res.body.error || 'The call failed.');
        render(res.body);
      })
      .catch(function (e) { status.textContent = e.message; })
      .finally(function () { go.disabled = false; });
  });

})();
