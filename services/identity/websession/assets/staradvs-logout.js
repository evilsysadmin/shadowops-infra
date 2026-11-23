'use strict';
// Staging Identity origin only. GET /logout never changes session state.
// Only this explicit click may POST to the same-origin central revoker.
const form = document.querySelector('#logout-form');
const status = document.querySelector('#status');
const submit = document.querySelector('#logout-submit');
form.addEventListener('submit', async event => {
  event.preventDefault();
  if (submit.disabled) return;
  submit.disabled = true;
  status.textContent = 'Revocando la sesión de ShadowOps ID…';
  try {
    const response = await fetch('/api/identity/logout', {
      method: 'POST',
      credentials: 'same-origin',
      redirect: 'error',
      headers: {'Content-Type': 'application/json'},
      body: '{}',
      signal: AbortSignal.timeout(10000),
    });
    // Do not claim logout or leave the IdP without a committed revocation.
    if (response.status !== 204) {
      status.textContent = 'No se ha confirmado el cierre de sesión. Puedes reintentarlo.';
      return;
    }
    window.location.replace(document.body.dataset.returnUrl);
  } catch {
    status.textContent = 'Identity no responde. No se ha confirmado el cierre de sesión.';
  } finally {
    submit.disabled = false;
  }
});
