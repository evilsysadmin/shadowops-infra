// Canonical catalog. The portal never assumes responsibility for game deployment.
export const WORLDS = Object.freeze([
  Object.freeze({
    id: 'chess',
    title: 'Chess Studio',
    kicker: 'Estrategia / Rivalidad / War Room',
    description: 'Una guerra de ingenio. Un rival que recuerda.',
    tone: '#d8ae72',
    destination: 'https://chess-studio.shadowops.dpdns.org/',
    state: 'external-unverified',
  }),
  Object.freeze({
    id: 'chronicles',
    title: 'Chronicles',
    kicker: 'Fantasía / Exploración / Mazmorras',
    description: 'Un mundo con más secretos que misericordia.',
    tone: '#d78556',
    destination: 'https://chronicles.shadowops.dpdns.org/',
    state: 'external-unverified',
  }),
  Object.freeze({
    id: 'star',
    title: 'Star Adventures',
    kicker: 'Espacio / Táctica / Descubrimiento',
    description: 'La siguiente frontera está tomando forma.',
    tone: '#75bed2',
    destination: null,
    state: 'in-development',
  }),
]);

export const RESERVED_WORLDS = Object.freeze([
  'Pawn Trailblazer', 'Fútbol', 'Tactics',
]);

export const isLaunchable = world =>
  world.state === 'external-unverified' && typeof world.destination === 'string';

export const worldById = id => WORLDS.find(world => world.id === id) ?? null;
