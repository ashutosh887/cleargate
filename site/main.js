// One moment of motion: the stamps land on the call slip once the type has loaded.
(function () {
  var root = document.documentElement;
  root.classList.add('js');
  var go = function () { requestAnimationFrame(function () { root.classList.add('go'); }); };
  if (document.fonts && document.fonts.ready) {
    Promise.race([document.fonts.ready, new Promise(function (r) { setTimeout(r, 900); })]).then(go);
  } else { go(); }
})();
