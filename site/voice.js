// Speak to the bank: hold the button, talk, let go. Sarvam hears it, both agents answer, and the
// gated agent's reply is played back. Fills #voice; hands the result to the try page's renderer.
(function () {
  var slot = document.getElementById('voice');
  if (!slot || !window.MediaRecorder || !navigator.mediaDevices) return;

  var MAX_MS = 20000;
  var el = function (tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  };
  var rupees = function (n) { return '\u20b9' + Number(n || 0).toLocaleString('en-IN'); };

  var btn = el('button', 'btn primary voice-btn', 'Hold to talk');
  btn.type = 'button';
  btn.setAttribute('aria-describedby', 'voice-status');
  var status = el('p', 'fine voice-status', 'Speak as the caller, in English, Hindi or both. Up to 20 seconds.');
  status.id = 'voice-status';
  status.setAttribute('aria-live', 'polite');
  var out = el('div', 'voice-out');
  slot.append(btn, status, out);

  var rec = null, chunks = [], timer = null, started = 0, player = null;

  function pickType() {
    var types = ['audio/webm;codecs=opus', 'audio/webm', 'audio/mp4', 'audio/ogg;codecs=opus'];
    for (var i = 0; i < types.length; i++) if (MediaRecorder.isTypeSupported(types[i])) return types[i];
    return '';
  }

  function start() {
    if (rec) return;
    navigator.mediaDevices.getUserMedia({ audio: true }).then(function (stream) {
      var type = pickType();
      rec = new MediaRecorder(stream, type ? { mimeType: type } : undefined);
      chunks = [];
      rec.ondataavailable = function (e) { if (e.data.size) chunks.push(e.data); };
      rec.onstop = function () {
        stream.getTracks().forEach(function (t) { t.stop(); });
        clearInterval(timer);
        var blob = new Blob(chunks, { type: (rec.mimeType || 'audio/webm').split(';')[0] });
        rec = null;
        btn.textContent = 'Hold to talk';
        btn.classList.remove('is-live');
        if (Date.now() - started < 600) { status.textContent = 'Hold the button while you speak.'; return; }
        send(blob);
      };
      rec.start();
      started = Date.now();
      btn.textContent = 'Listening, let go to send';
      btn.classList.add('is-live');
      timer = setInterval(function () {
        var left = Math.max(0, Math.ceil((MAX_MS - (Date.now() - started)) / 1000));
        status.textContent = 'Listening. ' + left + ' s left.';
        if (Date.now() - started >= MAX_MS) stop();
      }, 250);
    }).catch(function () {
      status.textContent = 'The microphone is blocked. Allow it in the browser, or type the caller line.';
    });
  }

  function stop() { if (rec && rec.state === 'recording') rec.stop(); }

  function play(b64, type) {
    if (!b64) return null;
    if (player) player.pause();
    player = new Audio('data:' + type + ';base64,' + b64);
    player.play().catch(function () {});
    return player;
  }

  function summary(res) {
    out.textContent = '';
    var s = res.panes.stock, g = res.panes.gated;
    out.appendChild(el('p', 'voice-heard', 'Heard: "' + res.transcript + '"'));
    var row = el('p', 'fine');
    row.textContent = 'Stock moved ' + rupees(s.moved_off_file_inr) + ' to accounts not on file. Gated moved ' +
      rupees(g.moved_off_file_inr) + '.';
    out.appendChild(row);
    [['gated', 'Play the gated reply'], ['stock', 'Play the stock reply']].forEach(function (p) {
      var b64 = res.audio && res.audio[p[0]];
      if (!b64) return;
      var b = el('button', 'btn', p[1]);
      b.type = 'button';
      b.addEventListener('click', function () { play(b64, res.audio_type); });
      out.appendChild(b);
    });
  }

  function send(blob) {
    btn.disabled = true;
    status.textContent = 'Sending the call…';
    var phoneEl = document.getElementById('phone');
    var phone = phoneEl ? phoneEl.textContent.trim() : '';
    fetch('/api/voice' + (phone ? '?phone=' + encodeURIComponent(phone) : ''), {
      method: 'POST', headers: { 'Content-Type': blob.type || 'audio/webm' }, body: blob
    })
      .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, body: j }; }); })
      .then(function (res) {
        if (!res.ok) throw new Error(res.body.error || 'The call failed.');
        var said = document.getElementById('said');
        if (said) said.value = res.body.transcript;
        if (typeof window.cleargateRender === 'function') window.cleargateRender(res.body);
        document.dispatchEvent(new CustomEvent('cleargate:result', { detail: res.body }));
        summary(res.body);
        status.textContent = 'The gated agent is answering.';
        play(res.body.audio && res.body.audio.gated, res.body.audio_type);
      })
      .catch(function (e) { status.textContent = e.message; })
      .finally(function () { btn.disabled = false; });
  }

  btn.addEventListener('pointerdown', function (e) { e.preventDefault(); start(); });
  btn.addEventListener('pointerup', stop);
  btn.addEventListener('pointerleave', stop);
  btn.addEventListener('pointercancel', stop);
  btn.addEventListener('keydown', function (e) {
    if ((e.key === ' ' || e.key === 'Enter') && !e.repeat) { e.preventDefault(); start(); }
  });
  btn.addEventListener('keyup', function (e) { if (e.key === ' ' || e.key === 'Enter') stop(); });
})();
