const { chromium } = require('playwright');
const { mkdir } = require('node:fs/promises');
const path = require('node:path');
const identity = 'https://id-staging.shadowops.dpdns.org';
const check = (condition, message) => { if (!condition) throw new Error(message); };
let browser;
(async () => {
  browser = await chromium.launch({ headless: true, executablePath: process.env.IDENTITY_BROWSER_EXECUTABLE || undefined,
    args: ['--no-proxy-server', '--host-resolver-rules=MAP id-staging.shadowops.dpdns.org 127.0.0.1:19443'] });
  const artifacts = process.env.IDENTITY_BROWSER_ARTIFACTS;
  if (artifacts) await mkdir(artifacts, { recursive: true });
  for (const [name, viewport] of [['desktop', {width:1280,height:800}], ['mobile', {width:390,height:844}]]) {
    const context = await browser.newContext({viewport, ignoreHTTPSErrors:true, isMobile:name==='mobile', hasTouch:name==='mobile'});
    const page = await context.newPage(); const errors=[];
    page.on('pageerror', error => errors.push(error.message));
    await page.goto(`${identity}/admin`);
    await page.getByLabel('Usuario', {exact:true}).fill('admin_browser');
    await page.getByLabel('Contraseña', {exact:true}).fill('correct-synthetic-password-2026');
    await page.getByRole('button', {name:'Entrar',exact:true}).click();
    await page.getByRole('heading', {name:'Cuentas',exact:true}).waitFor();
    check(await page.locator('#account-list').innerText().then(text=>text.includes('admin_browser')), 'account missing');
    check(await page.locator('#account-list').innerText().then(text=>text.includes('sesión vigente')), 'active session missing');
    check(await page.locator('#account-list').innerText().then(text=>text.includes('Intercambios de acceso (2 min): Chronicles')), 'recent access missing');
    const accountText=await page.locator('#account-list').innerText();
    check(accountText.includes('Cuenta creada:'), 'account creation date missing');
    check(accountText.includes('Canjes por aplicación: Chronicles') && accountText.includes('primero ') && accountText.includes('último '), 'access history missing');
    check(await page.locator('#history-note').isVisible(), 'history scope is not explained');
    check(await page.getByRole('link',{name:'Abrir Chronicles staging'}).getAttribute('href')==='https://staging.chronicles.shadowops.dpdns.org/', 'Chronicles staging link missing');
    check(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'admin page overflows viewport');
    if (artifacts) await page.screenshot({path:path.join(artifacts,`identity-admin-${name}.png`)});
    check(await page.locator('#account-list li').count()===20,'first page is not bounded');
    await page.getByRole('button',{name:'Ver más cuentas'}).click();
    await page.waitForFunction(()=>document.querySelectorAll('#account-list li').length===21);
    check(await page.getByRole('button',{name:'Ver más cuentas'}).isHidden(),'pagination did not finish');
    await Promise.all([page.waitForResponse(r=>r.url().endsWith('/api/identity/admin/accounts') && r.status()===200), page.getByRole('button',{name:'Actualizar'}).click()]);
    await page.waitForFunction(()=>document.querySelectorAll('#account-list li').length===20);
    await page.getByRole('button',{name:'Cerrar sesión'}).click();
    await page.getByRole('heading',{name:'Acceso de administrador'}).waitFor();
    check(errors.length===0,'browser JavaScript errors');
    await context.close(); console.log(`${name}: admin login, account list, refresh and logout passed`);
  }
})().catch(error => { console.error(error);process.exitCode=1; }).finally(async()=>{if(browser)await browser.close();});
