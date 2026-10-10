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

  function draw(mode, pane) {
    var gated = mode === 'gated';
    var box = document.getElementById('pane-' + mode);
    box.querySelectorAll(':scope > :not(h2)').forEach(function (n) { n.remove(); });
    var moved = pane.moved_off_file_inr || 0;
    var fig = el('p', 'moved');
    fig.appendChild(el('span', 'moved-label', 'Moved to accounts not on file'));
    fig.appendChild(el('span', 'moved-fig ' + (moved ? 'bad' : 'good'), rupees(moved)));
    box.appendChild(fig);
    box.appendChild(el('blockquote', 'reply', pane.reply || pane.error || ''));
    var list = el('ol', 'steps');
    (pane.steps || []).forEach(function (s) { list.appendChild(stepRow(s, gated)); });
    box.appendChild(list);
    box.appendChild(el('p', 'fine', (gated ? 'Decided by ' + pane.source + '. ' : 'No enforcement. ') + (pane.verified || '')));
  }

  form.addEventListener('submit', function (ev) {
    ev.preventDefault();
    var text = said.value.trim();
    if (!text) { said.focus(); return; }
    go.disabled = true;
    status.textContent = 'Calling…';
    fetch('/api/call', { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text: text, phone: callerPhone }) })
      .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, body: j }; }); })
      .then(function (res) {
        if (!res.ok) throw new Error(res.body.error || 'The call failed.');
        draw('stock', res.body.panes.stock);
        draw('gated', res.body.panes.gated);
        duel.hidden = false;
        status.textContent = 'Heard (' + res.body.language + '): "' + res.body.transcript + '"';
        duel.scrollIntoView({ behavior: 'smooth', block: 'start' });
      })
      .catch(function (e) { status.textContent = e.message; })
      .finally(function () { go.disabled = false; });
  });

  // Optional: the browser's own speech recognition, no server key involved.
  var SR = window.SpeechRecognition || window.webkitSpeechRecognition;
  if (SR) {
    var mic = document.getElementById('mic');
    var lang = document.getElementById('lang');
    mic.hidden = false;
    lang.hidden = false;
    var rec = null;
    mic.addEventListener('click', function () {
      if (rec) { rec.stop(); return; }
      rec = new SR();
      rec.lang = lang.value;
      rec.interimResults = true;
      rec.onresult = function (e) {
        said.value = Array.prototype.map.call(e.results, function (r) { return r[0].transcript; }).join(' ');
      };
      rec.onend = function () {
        mic.textContent = 'Speak';
        rec = null;
        if (said.value.trim()) form.requestSubmit();
      };
      rec.onerror = function (e) { status.textContent = 'Microphone: ' + e.error; };
      mic.textContent = 'Stop';
      status.textContent = 'Listening…';
      rec.start();
    });
  }
})();
