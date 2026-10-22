// A portal only launches its own environment. Never promote a staging visitor
// into production accidentally and never guess destinations for unknown hosts.
// The game projects and their DNS continue to be managed independently.
export const PORTAL_HOSTS = Object.freeze({
  staging: 'staging.shadowops.dpdns.org',
  production: 'shadowops.dpdns.org',
});
export function portalEnvironmentForHost(hostname) {
  if (hostname === PORTAL_HOSTS.staging) return 'staging';
  if (hostname === PORTAL_HOSTS.production) return 'production';
  return 'preview';
}

const WORLD_DATA = Object.freeze([
  Object.freeze({
    id: 'chess',
    title: 'Chess Studio',
    kicker: 'Estrategia / Rivalidad / War Room',
    description: 'Una guerra de ingenio. Un rival que recuerda.',
    tone: '#d8ae72',
    destinations: Object.freeze({
      staging: 'https://staging.chess-studio.shadowops.dpdns.org/',
      production: 'https://chess-studio.shadowops.dpdns.org/',
    }),
  }),
  Object.freeze({
    id: 'chronicles',
    title: 'Chronicles',
    kicker: 'Fantasía / Exploración / Mazmorras',
    description: 'Un mundo con más secretos que misericordia.',
    tone: '#d78556',
    destinations: Object.freeze({
      staging: 'https://staging.chronicles.shadowops.dpdns.org/',
      production: 'https://chronicles.shadowops.dpdns.org/',
    }),
  }),
  Object.freeze({
    id: 'star',
    title: 'Star Adventures',
    kicker: 'Espacio / Táctica / Descubrimiento',
    description: 'La siguiente frontera está tomando forma.',
    tone: '#75bed2',
    destinations: Object.freeze({
      // The staging Pages URL is published and verified by Infra CI.
      staging: 'https://staging.staradvs.shadowops.dpdns.org/',
      // Never invent a production link before a verified production release.
      production: null,
    }),
  }),
]);

export function worldsForHost(hostname) {
  const environment = portalEnvironmentForHost(hostname);
  return Object.freeze(WORLD_DATA.map(({destinations, ...world}) => {
    const destination = environment === 'preview' ? null : destinations[environment];
    return Object.freeze({
      ...world,
      destination,
      state: destination ? 'external-unverified' : 'in-development',
    });
  }));
}

// Production is the canonical catalog for static art identity. The actual
// browser catalog must be resolved from window.location.hostname at runtime.
export const WORLDS = worldsForHost(PORTAL_HOSTS.production);
export const RESERVED_WORLDS = Object.freeze([
  'Pawn Trailblazer', 'Fútbol', 'Tactics',
]);
export const isLaunchable = world =>
  world?.state === 'external-unverified' && typeof world.destination === 'string';
export const worldById = (id, worlds = WORLDS) =>
  worlds.find(world => world.id === id) ?? null;
