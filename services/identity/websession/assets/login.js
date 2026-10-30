'use strict';

const form = document.querySelector('#access-form');
const username = document.querySelector('#username');
const password = document.querySelector('#password');
const recovery = document.querySelector('#recovery');
const status = document.querySelector('#status');
const submit = document.querySelector('#submit');
const backup = document.querySelector('#backup');
const backupCode = document.querySelector('#backup-code');
let mode = 'login';
let busy = false;

function choose(next) {
  if (busy) return;
  mode = next;
  backup.hidden = true;
  backupCode.textContent = '';
  form.hidden = false;
  password.value = '';
  password.setCustomValidity('');
  recovery.value = '';
  recovery.required = next === 'recover';
  document.querySelector('#recovery-field').hidden = next !== 'recover';
  document.querySelector('#password-label').textContent = next === 'login' ? 'Contraseña' : 'Contraseña nueva';
  password.autocomplete = next === 'login' ? 'current-password' : 'new-password';
  password.minLength = next === 'login' ? 1 : 15;
  document.querySelector('#mode-hint').textContent = next === 'login' ? '' : next === 'register'
    ? 'Usa al menos 15 caracteres. Crear una cuenta no vincula cuentas anteriores.'
    : 'Usa al menos 15 caracteres. Recuperar el acceso cerrará tus sesiones abiertas.';
  submit.textContent = next === 'login' ? 'Entrar y continuar' : next === 'register' ? 'Crear mi cuenta ShadowOps' : 'Recuperar mi cuenta';
  document.querySelectorAll('[data-mode]').forEach(button => button.setAttribute('aria-pressed', String(button.dataset.mode === next)));
  status.textContent = '';
}

document.querySelectorAll('[data-mode]').forEach(button => button.addEventListener('click', () => choose(button.dataset.mode)));
document.querySelector('#backup-done').addEventListener('click', () => { choose('login'); password.focus(); });

form.addEventListener('submit', async event => {
  event.preventDefault();
  password.setCustomValidity(mode !== 'login' && [...password.value].length < 15 ? 'Usa al menos 15 caracteres.' : '');
  if (busy || !form.reportValidity()) return;
  busy = true;
  submit.disabled = true;
  document.querySelectorAll('[data-mode]').forEach(button => { button.disabled = true; });
  status.textContent = 'Comprobando…';
  const body = { username: username.value, password: password.value };
  if (mode === 'recover') body.recoveryCode = recovery.value;
  try {
    const response = await fetch(`/api/identity/${mode}`, {
      method: 'POST', credentials: 'same-origin', redirect: 'error',
      headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
      signal: AbortSignal.timeout(10000),
    });
    if (!response.ok) {
      status.textContent = response.status === 409 ? 'Ese usuario ya tiene una cuenta central. Prueba a iniciar sesión.'
        : response.status === 429 ? 'Has hecho varios intentos. Espera un minuto y vuelve a probar.'
        : response.status === 503 ? 'No podemos conectar ahora. Vuelve a intentarlo en unos instantes.'
        : 'No se ha podido completar. Comprueba el usuario, la contraseña o el código de recuperación.';
      return;
    }
    if (mode === 'login') {
      window.location.replace(document.body.dataset.returnUrl);
      return;
    }
    const result = await response.json();
    if (typeof result.recoveryCode !== 'string' || !/^sor1_[A-Za-z0-9_-]{43}$/.test(result.recoveryCode)) throw new Error('invalid recovery response');
    backupCode.textContent = result.recoveryCode;
    form.hidden = true;
    backup.hidden = false;
    status.textContent = '';
    document.querySelector('#backup-done').focus();
  } catch {
    status.textContent = 'No se ha podido conectar. Comprueba tu conexión y vuelve a intentarlo.';
  } finally {
    password.value = '';
    recovery.value = '';
    busy = false;
    submit.disabled = false;
    document.querySelectorAll('[data-mode]').forEach(button => { button.disabled = false; });
  }
});

password.addEventListener('input', () => password.setCustomValidity(''));
