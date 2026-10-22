import './style.css';
import { RESERVED_WORLDS, isLaunchable, worldById, worldsForHost, portalEnvironmentForHost } from './catalog.mjs';

const portalEnvironment = portalEnvironmentForHost(window.location.hostname);
const WORLDS = worldsForHost(window.location.hostname);
const selectedWorld = id => worldById(id, WORLDS);

const app = document.getElementById('app');
const el = (tag, className, text) => {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
};
const shell = el('div', 'shell');
shell.dataset.environment = portalEnvironment;
app.appendChild(shell);
const header = el('header', 'header');
const brand = el('a', 'brand', 'SHADOWOPS');
brand.href = '/';
brand.setAttribute('aria-label', 'ShadowOps Universe — inicio');
header.append(brand, el('span', 'header-aside',
  portalEnvironment === 'staging' ? 'STAGING · ENTORNO DE PRUEBAS' :
  portalEnvironment === 'production' ? 'INDEPENDENT WORLDS · ONE UNIVERSE' :
  'VISTA PREVIA · DESTINOS DESACTIVADOS'));
// At narrow widths the editorial header tagline disappears. Keep an
// unmistakable environment identity visible before the user enters a world.
if (portalEnvironment !== 'production') {
  const mobileEnvironment = el('span', 'mobile-environment',
    portalEnvironment === 'staging' ? 'STAGING' : 'PREVIEW');
  mobileEnvironment.setAttribute('aria-label', portalEnvironment === 'staging'
    ? 'Estás en la versión de pruebas de ShadowOps'
    : 'Vista previa: enlaces externos desactivados');
  header.appendChild(mobileEnvironment);
}
shell.appendChild(header);

const hero = el('main', 'hero');
const story = el('section', 'story');
story.append(
  el('p', 'eyebrow', 'EL UNIVERSO SHADOWOPS'),
  el('h1', 'headline', 'Hay mundos que no deberían existir.'),
  el('p', 'intro', 'Y, sin embargo, aquí están. Elige tu próxima obsesión.'),
);
const collectionTitle = el('h2', 'collection-title', 'Explora los mundos');
story.appendChild(collectionTitle);
const choices = el('div', 'choices');
story.appendChild(choices);
const footnote = el('p', 'footnote', 'Cada juego es independiente. ShadowOps es la puerta, no la jaula.');
story.appendChild(footnote);
hero.appendChild(story);

const stageArea = el('section', 'stage-area');
stageArea.setAttribute('aria-label', 'Observatorio tridimensional ShadowOps');
const stage = el('div', 'stage');
stage.dataset.scene = 'loading';
stageArea.appendChild(stage);
const eyebrow = el('div', 'stage-eyebrow', 'THE OBSERVATORY / 001');
stageArea.appendChild(eyebrow);
const tooltip = el('div', 'stage-footer', 'Toca un portal · Arrastra suavemente para mirar');
stageArea.appendChild(tooltip);
const fallback = el('div', 'fallback');
fallback.setAttribute('aria-hidden', 'true');
fallback.append(el('div', 'fallback-orb'), el('p', 'fallback-text', 'TRES PUERTAS. INFINITOS UNIVERSOS.'));
stage.appendChild(fallback);
hero.appendChild(stageArea);
shell.appendChild(hero);

const footer = el('footer', 'footer');
footer.append(
  el('span', '', 'SHADOWOPS · A COLLECTION OF BEAUTIFUL OBSESSIONS'),
  el('span', '', 'PRÓXIMAMENTE: ' + RESERVED_WORLDS.join(' / '))
);
shell.appendChild(footer);

let selected = 'chess';
let pointerPreview = null;
let focusPreview = null;
let scene = null;
const buttons = new Map();
const detail = el('div', 'world-detail');
detail.setAttribute('aria-live', 'polite');
detail.setAttribute('aria-atomic', 'true');
stageArea.appendChild(detail);

function renderDetail() {
  const world = selectedWorld(selected);
  detail.replaceChildren();
  const copy = el('div', 'detail-copy');
  copy.append(el('p', 'detail-kicker', world.kicker), el('h2', 'detail-title', world.title), el('p', 'detail-description', world.description));
  detail.appendChild(copy);
  if (isLaunchable(world)) {
    const link = el('a', 'enter-link', portalEnvironment === 'staging'
      ? 'Entrar · staging ↗' : 'Visitar mundo ↗');
    link.setAttribute('aria-label', `Abrir ${world.title} en ${portalEnvironment === 'staging' ? 'staging' : 'producción'}`);
    link.href = world.destination;
    link.rel = 'noopener noreferrer';
    link.title = portalEnvironment === 'staging'
      ? 'Abrir el mundo en staging' : 'Abrir el mundo en producción';
    detail.appendChild(link);
  } else {
    detail.appendChild(el('span', 'unavailable', 'EN DESARROLLO'));
  }
  choices.querySelectorAll('button').forEach(button => {
    const active = button.dataset.world === selected;
    button.classList.toggle('active', active);
    button.setAttribute('aria-pressed', String(active));
  });
}
// A gallery preview is only visual. It must never silently change the
// selected game, launch destination or aria-pressed state.
function refreshSceneFocus(moveCamera = true) {
  scene?.focusWorld(focusPreview ?? pointerPreview ?? selected, moveCamera);
}
function selectWorld(id) {
  if (!selectedWorld(id)) return;
  selected = id;
  renderDetail();
  refreshSceneFocus();
}
WORLDS.forEach((world, index) => {
  const button = el('button', 'world-button');
  button.type = 'button';
  button.dataset.world = world.id;
  const number = el('span', 'world-number', '0' + (index + 1));
  const label = el('span', 'world-label');
  label.append(el('strong', '', world.title), el('small', '', world.kicker));
  const chevron = el('span', 'world-chevron', '↗');
  chevron.setAttribute('aria-hidden', 'true');
  button.append(number, label, chevron);
  button.addEventListener('click', () => selectWorld(world.id));
  // Do not emulate hover on touch: tap remains the single select action.
  button.addEventListener('pointerenter', event => {
    if (event.pointerType !== 'mouse' && event.pointerType !== 'pen') return;
    pointerPreview = world.id;
    refreshSceneFocus();
  });
  button.addEventListener('pointerleave', () => {
    if (pointerPreview !== world.id) return;
    pointerPreview = null;
    refreshSceneFocus();
  });
  button.addEventListener('focus', () => {
    focusPreview = world.id;
    refreshSceneFocus();
  });
  button.addEventListener('blur', () => {
    if (focusPreview !== world.id) return;
    focusPreview = null;
    refreshSceneFocus();
  });
  button.style.setProperty('--accent', world.tone);
  choices.appendChild(button);
  buttons.set(world.id, button);
});
renderDetail();

/**
 * The catalog and launch links are interactive before the ~Three.js runtime
 * downloads. WebGL is enhancement, never a dependency for navigation.
 */
let sceneLoadStarted = false;
let sceneObserver = null;
function showFallback(reason) {
  stage.dataset.scene = reason;
  stage.classList.add('no-webgl');
  fallback.hidden = false;
  tooltip.textContent = 'El catálogo funciona también sin 3D';
}
async function loadScene() {
  if (sceneLoadStarted) return;
  sceneLoadStarted = true;
  sceneObserver?.disconnect();
  sceneObserver = null;
  if (!window.WebGLRenderingContext) {
    showFallback('unavailable');
    return;
  }
  try {
    const { mountObservatory } = await import('./world.js');
    scene = mountObservatory(stage, selectWorld);
    refreshSceneFocus(false);
    fallback.hidden = true;
    stage.dataset.scene = 'active';
    const canvas = stage.querySelector('canvas');
    canvas?.addEventListener('webglcontextlost', () => {
      showFallback('lost');
    });
    canvas?.addEventListener('webglcontextrestored', () => {
      if (scene) {
        stage.classList.remove('no-webgl');
        stage.dataset.scene = 'active';
        fallback.hidden = true;
        refreshSceneFocus(false);
      }
    });
  } catch (error) {
    console.warn('ShadowOps: WebGL unavailable, using accessible catalog.', error);
    scene?.destroy();
    scene = null;
    showFallback('unavailable');
  }
}
if ('IntersectionObserver' in window) {
  sceneObserver = new IntersectionObserver(entries => {
    if (entries.some(entry => entry.isIntersecting)) void loadScene();
  }, { rootMargin: '160px 0px', threshold: 0 });
  sceneObserver.observe(stageArea);
} else {
  // Old browsers still get the accessible catalog immediately.
  void loadScene();
}
