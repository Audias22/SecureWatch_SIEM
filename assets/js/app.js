// Interacciones sin JavaScript en línea (compatibles con Content-Security-Policy).
document.addEventListener('submit', function (e) {
  var msg = e.target.getAttribute('data-confirm');
  if (msg && !window.confirm(msg)) e.preventDefault();
});
document.addEventListener('click', function (e) {
  if (e.target.closest('[data-print]')) window.print();
});

// Botón para mostrar u ocultar contraseñas. Siempre empiezan ocultas; solo el usuario decide verlas.
document.querySelectorAll('input[type="password"]').forEach(function (input) {
  var group = document.createElement('div');
  group.className = 'input-group' + (input.classList.contains('form-control-sm') ? ' input-group-sm' : '');
  if (input.style.width) { group.style.width = input.style.width; input.style.width = ''; }
  var mb = Array.prototype.filter.call(input.classList, function (c) { return /^mb-\d$/.test(c); });
  mb.forEach(function (c) { input.classList.remove(c); group.classList.add(c); });
  input.parentNode.insertBefore(group, input);
  group.appendChild(input);
  var btn = document.createElement('button');
  btn.type = 'button';
  btn.className = 'btn btn-outline-secondary pw-toggle';
  btn.setAttribute('aria-label', 'Mostrar contraseña');
  btn.title = 'Mostrar contraseña';
  btn.textContent = 'Ver';
  btn.addEventListener('click', function () {
    var show = input.type === 'password';
    input.type = show ? 'text' : 'password';
    btn.textContent = show ? 'Ocultar' : 'Ver';
    btn.setAttribute('aria-label', show ? 'Ocultar contraseña' : 'Mostrar contraseña');
    btn.title = btn.getAttribute('aria-label');
    input.focus();
  });
  group.appendChild(btn);
  // Al enviar el formulario se vuelve a ocultar, para que el navegador no la guarde como texto visible.
  if (input.form) input.form.addEventListener('submit', function () { input.type = 'password'; });
});

// La terminal del colector muestra primero las líneas más recientes (al final).
document.querySelectorAll('pre.term').forEach(function (t) { t.scrollTop = t.scrollHeight; });
