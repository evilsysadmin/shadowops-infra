import './style.css';
import { WORLDS, RESERVED_WORLDS, isLaunchable, worldById } from './catalog.mjs';
import { mountObservatory } from './world.js';

const app = document.getElementById('app');
const el = (tag, className, text) => {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
};
const shell = el('div', 'shell');
app.appendChild(shell);
const header = el('header', 'header');
const brand = el('a', 'brand', 'SHADOWOPS');
brand.href = '/';
brand.setAttribute('aria-label', 'ShadowOps Universe — inicio');
header.append(brand, el('span', 'header-aside', 'INDEPENDENT WORLDS · ONE UNIVERSE'));
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
let scene = null;
const buttons = new Map();
const detail = el('div', 'world-detail');
stageArea.appendChild(detail);

function renderDetail() {
  const world = worldById(selected);
  detail.replaceChildren();
  const copy = el('div', 'detail-copy');
  copy.append(el('p', 'detail-kicker', world.kicker), el('h2', 'detail-title', world.title), el('p', 'detail-description', world.description));
  detail.appendChild(copy);
  if (isLaunchable(world)) {
    const link = el('a', 'enter-link', 'Visitar mundo ↗');
    link.href = world.destination;
    link.rel = 'noopener noreferrer';
    link.title = 'Destino externo; disponibilidad no verificada';
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
function selectWorld(id) {
  if (!worldById(id)) return;
  selected = id;
  renderDetail();
  scene?.focusWorld(id);
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
  button.style.setProperty('--accent', world.tone);
  choices.appendChild(button);
  buttons.set(world.id, button);
});
renderDetail();

try {
  scene = mountObservatory(stage, selectWorld);
  fallback.hidden = true;
} catch (error) {
  console.warn('ShadowOps: WebGL unavailable, using accessible catalog.', error);
  stage.classList.add('no-webgl');
  tooltip.textContent = 'Los accesos a los juegos siguen disponibles';
}
