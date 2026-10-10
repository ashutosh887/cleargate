// Try a call: post the caller's line to /api/call, then play both runs back step by step in lockstep.
(function () {
  var form = document.getElementById('dial');
  var said = document.getElementById('said');
  var phone = document.getElementById('phone');
  var status = document.getElementById('status');
  var live = document.getElementById('live');
  var meta = document.getElementById('meta');
  var go = document.getElementById('go');
  var duel = document.getElementById('duel');
  var cards = document.getElementById('cards');
  var callerPhone = '+91-98123-45678';
  var domain = 'bank';
  var preset = null;
  var bankCards = cards.innerHTML;
  var reduce = window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches;
  var STEP_MS = reduce ? 0 : 210;
  var runId = 0;

  var rupees = function (n) { return '₹' + Number(n || 0).toLocaleString('en-IN'); };
  var el = function (tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  };
  var wait = function (ms) { return new Promise(function (r) { setTimeout(r, ms); }); };

  // ---- caller cards ----
  function bindCards() {
    cards.querySelectorAll('.card').forEach(function (b) {
      b.setAttribute('aria-pressed', 'false');
      b.addEventListener('click', function () {
        said.value = b.dataset.text;
        preset = b.dataset.preset || null;
        if (b.dataset.phone) { callerPhone = b.dataset.phone; phone.textContent = callerPhone; }
        cards.querySelectorAll('.card').forEach(function (o) { o.setAttribute('aria-pressed', String(o === b)); });
        form.requestSubmit();
      });
    });
  }
  bindCards();
  said.addEventListener('input', function () {
    preset = null;
    cards.querySelectorAll('.card').forEach(function (o) { o.setAttribute('aria-pressed', 'false'); });
  });

  // ---- steps ----
  var CHIP = { ALLOW: 'c-allow', NARROW: 'c-narrow', BLOCK: 'c-block', ESCALATE: 'c-escalate', UNGUARDED: 'c-none' };
  var LABEL = { UNGUARDED: 'No gate' };

  function argText(args) {
    return Object.keys(args || {}).map(function (k) {
      var v = args[k];
      return k + '=' + (k === 'amount_inr' ? rupees(v) : String(v));
    }).join('  ');
  }
  function clean(r) { return (r || '').replace(/^\[local-simulation: [^\]]+\]\s*/, ''); }
  function key(s) { return s.kind + ':' + (s.tool || ''); }

  // Pair the two runs row by row so the same tool call sits on the same line.
  function align(a, b) {
    var rows = [], i = 0, j = 0;
    while (i < a.length || j < b.length) {
      var s = a[i], g = b[j];
      if (s && g && key(s) === key(g)) { rows.push([s, g]); i++; j++; continue; }
      if (g && (!s || g.kind === 'notice' || !a.slice(i).some(function (x) { return key(x) === key(g); }))) {
        rows.push([null, g]); j++; continue;
      }
      rows.push([s, null]); i++;
    }
    return rows;
  }

  function stepCard(s, gated) {
    var li = el('li', 'step');
    if (!s) { li.classList.add('gap'); li.appendChild(el('span', 'gap-line', gated ? 'not offered' : 'no step here')); return li; }
    var chip = el('span', 'chip ' + (CHIP[s.verb] || 'c-none'), LABEL[s.verb] || s.verb);
    var top = el('div', 'step-top');
    top.appendChild(chip);
    var what = s.tool || (s.kind === 'task_open' ? 'task opened' : 'tools narrowed');
    var name = el('span', 'step-tool', what);
    if (!s.tool) name.classList.add('meta');
    top.appendChild(name);
    if (s.agent) top.appendChild(el('span', 'agent', s.agent));
    li.appendChild(top);
    var a = argText(s.args);
    if (a) {
      var args = el('button', 'args', a);
      args.type = 'button';
      args.title = 'Show all arguments';
      args.setAttribute('aria-expanded', 'false');
      args.addEventListener('click', function () {
        var open = args.getAttribute('aria-expanded') !== 'true';
        args.setAttribute('aria-expanded', String(open));
      });
      li.appendChild(args);
    }
    var reason = clean(s.reason);
    if (s.rule || reason || s.denial_step) {
      var d = el('details', 'why');
      var sum = el('summary');
      sum.appendChild(el('span', null, gated ? 'Rule ' : (s.rule ? 'Flag ' : 'Note ')));
      if (s.rule) sum.appendChild(el('code', null, s.rule));
      d.appendChild(sum);
      if (reason) d.appendChild(el('p', null, reason));
      if (s.denial_step) d.appendChild(el('p', 'sim', 'Simulated: ' + s.denial_step.replace(/^local-simulation:\s*/, '')));
      li.appendChild(d);
    }
    if (!gated && s.tool && s.rule) li.classList.add('flagged');
    if (s.verb === 'BLOCK') li.classList.add('blocked');
    return li;
  }

  function paneShell(mode, pane, labels) {
    var box = document.getElementById('pane-' + mode);
    box.textContent = '';
    var head = el('header', 'pane-head');
    var title = el('div', 'pane-title');
    title.appendChild(el('span', 'pane-dot'));
    title.appendChild(el('h2', null, mode === 'gated' ? 'Same agent, gated' : 'Stock agent, no gate'));
    head.appendChild(title);
    var fig = el('div', 'moved');
    fig.appendChild(el('span', 'moved-label', labels.label));
    var num = el('span', 'moved-fig', labels.zero);
    fig.appendChild(num);
    head.appendChild(fig);
    var reply = el('blockquote', 'reply pending');
    reply.appendChild(el('span', 'reply-who', 'Agent says'));
    var rtext = el('span', 'reply-text', 'On the line…');
    reply.appendChild(rtext);
    head.appendChild(reply);
    box.appendChild(head);
    var list = el('ol', 'steps');
    box.appendChild(list);
    var foot = el('footer', 'pane-foot');
    box.appendChild(foot);
    return { box: box, num: num, reply: reply, rtext: rtext, list: list, foot: foot, pane: pane, mode: mode };
  }

  function divergeIndex(rows) {
    for (var k = 0; k < rows.length; k++) {
      var s = rows[k][0], g = rows[k][1];
      if (s && g && s.tool && s.executed && !g.executed) return k;
      if (s && g && s.tool && s.rule && g.verb === 'BLOCK') return k;
    }
    return -1;
  }

  function finish(p, labels) {
    var pane = p.pane;
    p.num.textContent = labels.fmt(labels.total(p));
    if (labels.headline) {
      p.num.classList.add('headline');
      var hl = String(labels.total(p));
      var m = hl.match(/(\d+) of (\d+)/);
      p.num.classList.add(m ? (+m[1] ? 'bad' : 'good') : (p.mode === 'gated' ? 'good' : 'bad'));
    } else p.num.classList.add(labels.total(p) ? 'bad' : 'good');
    p.rtext.textContent = pane.reply || pane.error || '';
    p.reply.classList.remove('pending');
    p.foot.textContent = '';
    var ok = /^MATCH/.test(pane.verified || '');
    var line = el('p', 'match ' + (ok ? 'ok' : 'bad'));
    line.appendChild(el('span', 'match-k', ok ? 'MATCH' : 'CHECK'));
    line.appendChild(document.createTextNode(' ' + (pane.verified || '').replace(/^MATCH:\s*/, '')));
    p.foot.appendChild(line);
    var src = el('p', 'src', p.mode === 'gated' ? 'Decided by ' + pane.source + '.' : 'No enforcement on this run.');
    if (pane.record) {
      var a = el('a', null, 'Download the signed record');
      a.href = '#';
      a.addEventListener('click', function (ev) {
        if (a.download) return;
        ev.preventDefault();
        a.href = URL.createObjectURL(new Blob([pane.record], { type: 'application/x-ndjson' }));
        a.download = 'cleargate-' + p.mode + '.jsonl';
        a.click();
      });
      src.appendChild(document.createTextNode(' '));
      src.appendChild(a);
    }
    p.foot.appendChild(src);
  }

  function labelsFor(body) {
    if (domain === 'bank') {
      return {
        label: 'Sent to accounts not on file', zero: rupees(0), fmt: rupees,
        total: function (p) { return p.pane.moved_off_file_inr || 0; },
        add: function (p, s) { return s.executed && s.tool && /refund|transfer|send/.test(s.tool) && s.args ? Number(s.args.amount_inr || 0) : 0; }
      };
    }
    return {
      label: 'Outcome', zero: '…', fmt: String, headline: true,
      total: function (p) { return p.pane.headline || ''; },
      add: function () { return 0; }
    };
  }

  function setMeta(pairs) {
    meta.textContent = '';
    pairs.forEach(function (kv) {
      var d = el('div');
      d.appendChild(el('dt', null, kv[0]));
      d.appendChild(el('dd', null, kv[1]));
      meta.appendChild(d);
    });
  }

  async function play(body, ms) {
    var my = ++runId;
    var labels = labelsFor(body);
    var st = paneShell('stock', body.panes.stock, labels);
    var gt = paneShell('gated', body.panes.gated, labels);
    var rows = align(body.panes.stock.steps || [], body.panes.gated.steps || []);
    var split = divergeIndex(rows);
    var stamp = new Date();
    setMeta([
      ['Round trip', ms + ' ms'],
      ['Run at', stamp.toLocaleTimeString('en-IN', { timeZone: 'Asia/Kolkata', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }) + ' IST'],
      ['Engine', body.engine || 'scripted agents'],
      ['Heard', (body.language || 'en-IN')],
      ['Steps', rows.length + ' per run']
    ]);
    duel.hidden = false;
    duel.style.setProperty('--span', rows.length + 2);
    status.textContent = 'Answered. Playing both runs back.';
    live.classList.remove('ringing');
    live.classList.add('playing');
    live.scrollIntoView({ behavior: reduce ? 'auto' : 'smooth', block: 'start' });
    var run = { stock: 0, gated: 0 };
    st.unsafe = 0; gt.unsafe = 0;
    for (var k = 0; k < rows.length; k++) {
      if (my !== runId) return;
      var isSplit = k === split;
      if (isSplit && STEP_MS) await wait(STEP_MS * 2);
      [[st, rows[k][0], false], [gt, rows[k][1], true]].forEach(function (x) {
        var li = stepCard(x[1], x[2]);
        if (isSplit) li.classList.add('split');
        x[0].list.appendChild(li);
        if (x[1]) {
          var add = labels.add(x[0], x[1]);
          var cap = labels.total(x[0]);
          if (add && cap) {
            run[x[0].mode] = Math.min(cap, run[x[0].mode] + add);
            x[0].num.textContent = labels.fmt(run[x[0].mode]);
            x[0].num.classList.add('bad', 'bump');
          }
          if (!x[2] && x[1].rule && x[1].tool && x[1].executed) st.unsafe++;
        }
      });
      if (isSplit) {
        var tag = el('span', 'split-tag', 'The runs split here');
        gt.list.lastChild.prepend(tag);
        status.textContent = rows[k][1] && rows[k][1].verb === 'BLOCK' ? 'Same request, two outcomes: the gate blocks it.' : 'The runs split here.';
      }
      if (STEP_MS) await wait(isSplit ? STEP_MS * 3 : STEP_MS);
    }
    if (my !== runId) return;
    finish(st, labels);
    finish(gt, labels);
    var moved = labels.total(st);
    status.textContent = domain === 'bank'
      ? (moved ? 'Without the gate, ' + rupees(moved) + ' left for an account not on file. With it, ' + rupees(labels.total(gt)) + '.' : 'Both runs kept the money on file.')
      : 'Done. Both records verified.';
    live.classList.remove('playing');
    live.classList.add('done');
  }

  // voice.js hands spoken calls to the same renderer.
  window.cleargateRender = function (body, ms) { return play(body, ms == null ? '—' : ms); };

  var ticker = null;
  function ringing(useLive) {
    live.hidden = false;
    live.className = 'live ringing';
    setMeta([['Engine', useLive ? 'live model' : 'scripted agents']]);
    var t0 = performance.now();
    status.textContent = 'Calling the support line…';
    clearInterval(ticker);
    ticker = setInterval(function () {
      var ms = performance.now() - t0;
      var t = useLive ? (ms / 1000).toFixed(1) + ' s' : Math.round(ms) + ' ms';
      status.textContent = (useLive
        ? (ms < 4000 ? 'The model is taking the call, twice…' : 'Still on the line. Live calls take 5 to 20 s… ')
        : 'Both runs in progress on the server… ') + ' ' + t;
    }, 100);
    // Skeleton rows so the panes are visibly working while the server runs.
    duel.hidden = false;
    duel.style.setProperty('--span', 6);
    ['stock', 'gated'].forEach(function (m) {
      var box = document.getElementById('pane-' + m);
      box.textContent = '';
      var h = el('header', 'pane-head');
      var t = el('div', 'pane-title');
      t.appendChild(el('span', 'pane-dot'));
      t.appendChild(el('h2', null, m === 'gated' ? 'Same agent, gated' : 'Stock agent, no gate'));
      h.appendChild(t);
      box.appendChild(h);
      var ol = el('ol', 'steps skeleton');
      for (var i = 0; i < 4; i++) ol.appendChild(el('li', 'step ghost'));
      box.appendChild(ol);
    });
    return t0;
  }

  // ---- engine: live model when the API reports it, else scripted ----
  var engineBox = document.getElementById('engine');
  var fallback = document.getElementById('fallback');
  fetch('/api/live').then(function (r) { return r.ok ? r.json() : null; }).then(function (j) {
    if (!j || !j.available) return;
    engineBox.hidden = false;
    if (j.engine) engineBox.querySelector('input[value="live"] + span').textContent = 'Live model (' + (/gemini/i.test(j.engine) ? 'Gemini' : j.engine) + ')';
  }).catch(function () {});
  function engine() {
    var c = engineBox.querySelector('input:checked');
    return !engineBox.hidden && domain === 'bank' && c ? c.value : 'scripted';
  }

  function place(useLive) {
    var text = said.value.trim();
    go.disabled = true;
    fallback.hidden = true;
    runId++;
    var t0 = ringing(useLive);
    var payload = domain === 'bank' ? { text: text, phone: callerPhone } : { domain: domain, preset: preset, text: text };
    fetch(useLive ? '/api/live' : '/api/call', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) })
      .then(function (r) { return r.json().catch(function () { return {}; }).then(function (j) { return { ok: r.ok, code: r.status, body: j }; }); })
      .then(function (res) {
        clearInterval(ticker);
        if (useLive && !res.ok && (res.code === 503 || res.code === 429 || res.body.fallback === 'scripted')) {
          duel.hidden = true;
          live.className = 'live error';
          status.textContent = 'The live model is unavailable right now.';
          setMeta([]);
          fallback.hidden = false;
          return;
        }
        if (!res.ok) throw new Error(res.body.message || res.body.error || 'The call failed.');
        if (!res.body.engine) res.body.engine = useLive ? 'live model' : 'scripted agents';
        return play(res.body, Math.round(performance.now() - t0));
      })
      .catch(function (e) {
        clearInterval(ticker);
        duel.hidden = true;
        live.className = 'live error';
        status.textContent = e.message;
      })
      .finally(function () { go.disabled = false; });
  }
  document.getElementById('fallback-go').addEventListener('click', function () { place(false); });

  form.addEventListener('submit', function (ev) {
    ev.preventDefault();
    if (!said.value.trim() && !preset) { said.focus(); return; }
    place(engine() === 'live');
  });

  // ---- domain tabs: only shown if the API offers a second agent ----
  var tabs = document.getElementById('domains');
  var devopsPresets = null;
  fetch('/api/call?domain=devops').then(function (r) { return r.ok ? r.json() : null; }).then(function (j) {
    if (!j || !Array.isArray(j.presets) || !j.presets.length) return;
    devopsPresets = j.presets;
    tabs.hidden = false;
  }).catch(function () {});

  var bankFine = document.querySelector('.try-fine').innerHTML;
  function setDomain(d) {
    domain = d;
    preset = null;
    tabs.querySelectorAll('.domain').forEach(function (b) { b.setAttribute('aria-pressed', String(b.dataset.domain === d)); });
    var bank = d === 'bank';
    document.querySelector('#presets legend').textContent = bank ? '1. Pick a caller' : '1. Pick a request';
    document.getElementById('said-label').textContent = bank ? '2. Or say your own line' : '2. The request the team gets';
    said.readOnly = !bank;
    document.querySelector('.try-fine').innerHTML = bank ? bankFine
      : 'Decisions on this page come from a local stand-in for AgntID (<code>cleargate check --stub</code>), with scripted agents on stub GitHub, a stub database and a local outbox. Every run writes a signed record, and the page shows it only after the signatures verify.';
    document.querySelector('.try-generic').firstChild.textContent = 'ClearGate is a go-live gate for any AI agent that can move money, change code or read customer data. ' + (bank ? 'The bank call is one example. ' : 'The coding team is one example. ');
    document.getElementById('from').hidden = !bank;
    document.getElementById('voice').hidden = !bank;
    go.textContent = bank ? 'Place the call' : 'Run the agent';
    document.querySelector('.try-head h1').textContent = bank ? 'Call the bank' : 'Brief the coding agent';
    document.querySelector('.try-head .lede').textContent = bank
      ? 'Pick a caller or type your own line. The same support team takes the call twice: once with no gate, once behind the policy. Both runs happen on the server when you press the button.'
      : 'Pick a task. The same coding team runs it twice on a payments repo: once with no gate, once behind the policy. Both runs happen on the server when you press the button.';
    if (bank) { cards.innerHTML = bankCards; }
    else {
      cards.textContent = '';
      devopsPresets.forEach(function (p) {
        var b = el('button', 'card');
        b.type = 'button';
        b.dataset.text = p.text;
        b.dataset.preset = p.id;
        b.appendChild(el('b', null, p.label));
        b.appendChild(el('span', 'hook', p.text || ''));
        cards.appendChild(b);
      });
    }
    said.value = '';
    bindCards();
    duel.hidden = true;
    live.hidden = true;
    engineBox.classList.toggle('off', !bank);
  }
  tabs.querySelectorAll('.domain').forEach(function (b) {
    b.addEventListener('click', function () { if (b.dataset.domain !== domain) setDomain(b.dataset.domain); });
  });
})();
