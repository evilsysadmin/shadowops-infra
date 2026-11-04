(() => {
  const $ = id => document.getElementById(id);
  let cursor = '';
  const labels={'chess-studio':'Chess Studio','chronicles':'Chronicles','cka-simulator':'CKA','football':'Football','pawn-action':'Pawn Action'};
  const status = message => { $('status').textContent = message; };
  async function send(path, body) {
    return fetch(path, {method:'POST', credentials:'same-origin', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)});
  }
  function accountItem(account, recentAccessAvailable, accessHistoryAvailable) {
    const item=document.createElement('li'); item.className='account';
    const identity=document.createElement('div'); const name=document.createElement('strong'); name.textContent=account.name;
    const id=document.createElement('small'); id.textContent=account.subject; identity.append(name,id);
    if (recentAccessAvailable) { const games=(account.recentApplications || []).map(a=>labels[a.application]).filter(Boolean); const recent=document.createElement('small'); recent.textContent=games.length?'Intercambios de acceso (2 min): '+games.join(', '):'Sin intercambios recientes visibles'; identity.append(recent); }
    if (accessHistoryAvailable) { const history=Array.isArray(account.accessHistory)?account.accessHistory:[]; const item=document.createElement('small'); const valid=history.filter(a=>labels[a.application] && Number.isFinite(Date.parse(a.lastAt))); item.textContent=valid.length?'Último canje registrado: '+valid.map(a=>labels[a.application]+' · '+new Intl.DateTimeFormat('es',{dateStyle:'medium',timeStyle:'short'}).format(new Date(a.lastAt))).join('; '):'Sin canjes registrados desde la activación'; identity.append(item); }
    const badge=document.createElement('span'); const enabled=account.state==='active' && !account.credentialsDisabled;
    badge.className=enabled?'badge':'badge disabled'; badge.textContent=enabled?'Activa':account.credentialsDisabled?'Acceso deshabilitado':'No activa';
    const sessions=document.createElement('div'); sessions.className='sessions';
    const count=document.createElement('strong'); count.textContent=String(account.currentSessions);
    const label=document.createElement('small'); label.textContent=account.currentSessions===1?'sesión vigente':'sesiones vigentes'; sessions.append(count,label);
    item.append(identity,badge,sessions); return item;
  }
  async function load(append=false) {
    status('Cargando cuentas…'); $('next').disabled=true; $('refresh').disabled=true; $('logout').disabled=true;
    try {
      const response=await send('/api/identity/admin/accounts',{after:append?cursor:'',limit:20});
      if (response.status===401) { $('account-list').replaceChildren(); cursor=''; $('next').hidden=true; $('signin').hidden=false; $('accounts').hidden=true; $('logout').hidden=true; status('Inicia sesión con una cuenta administradora.'); return; }
      if (!response.ok) throw Error('unavailable');
      const page=await response.json(); if (!Array.isArray(page.accounts)) throw Error('invalid');
      if (!append) $('account-list').replaceChildren();
      for (const account of page.accounts) $('account-list').append(accountItem(account,page.recentAccessAvailable,page.accessHistoryAvailable));
      cursor=typeof page.next==='string'?page.next:''; $('next').hidden=!cursor;
      $('history-note').hidden=!page.accessHistoryAvailable; $('empty').hidden=$('account-list').children.length!==0; $('signin').hidden=true; $('accounts').hidden=false; $('logout').hidden=false; status('');
    } catch { status('No se pudieron cargar las cuentas. Inténtalo de nuevo.'); }
    finally { $('next').disabled=false; $('refresh').disabled=false; $('logout').disabled=false; }
  }
  $('login').addEventListener('submit',async event=>{event.preventDefault();const button=event.submitter;button.disabled=true;status('Iniciando sesión…');try{const response=await send('/api/identity/login',{username:$('username').value,password:$('password').value});$('password').value='';if(!response.ok){status('No se pudo iniciar sesión. Revisa tus datos.');return;}await load();}catch{status('No se pudo conectar con Identity.');}finally{button.disabled=false;}});
  $('refresh').addEventListener('click',()=>load()); $('next').addEventListener('click',()=>load(true));
  $('logout').addEventListener('click',async()=>{try{const response=await send('/api/identity/logout',{});if(!response.ok)throw Error('logout');$('account-list').replaceChildren();$('accounts').hidden=true;$('logout').hidden=true;$('signin').hidden=false;cursor='';status('Sesión cerrada.');}catch{status('No se pudo cerrar la sesión.');}});
  load();
})();
