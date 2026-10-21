import * as THREE from 'three';
import { WORLDS } from './catalog.mjs';

// A self-contained atmospheric observatory. No borrowed Chess Studio models.
// Source-authored GLB/texture art can replace the gateways in a later art PR.
const PORTAL_VERTEX = `
  varying vec2 vUv;
  void main() {
    vUv = uv;
    gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
  }
`;
const PORTAL_FRAGMENT = `
  uniform float uTime;
  uniform float uFocus;
  uniform vec3 uTint;
  varying vec2 vUv;
  float hash(vec2 p) {
    return fract(sin(dot(p, vec2(127.1, 311.7))) * 43758.5453);
  }
  float noise(vec2 p) {
    vec2 i = floor(p), f = fract(p);
    f = f * f * (3.0 - 2.0 * f);
    return mix(mix(hash(i), hash(i + vec2(1.,0.)), f.x),
      mix(hash(i + vec2(0.,1.)), hash(i + vec2(1.,1.)), f.x), f.y);
  }
  void main() {
    vec2 p = (vUv - .5) * vec2(1., 1.6);
    float radius = length(p);
    float warp = noise(p * 4.0 + vec2(uTime * .045, -uTime * .03));
    float arcs = sin(radius * 24. - uTime * .35 + warp * 3.);
    float veil = noise(p * 8. + uTime * .024) * .45
       + noise(p * 17. - uTime * .018) * .22;
    float interior = smoothstep(.88, .33, radius);
    float halo = pow(max(0., 1. - abs(radius - .75) * 5.), 2.);
    float shimmer = clamp(.13 + veil * .5 + arcs * .042 + uFocus * .12, 0., 1.);
    vec3 color = mix(vec3(.012, .024, .045), uTint * (.34 + veil * .55), shimmer);
    color += uTint * halo * (.10 + uFocus * .1);
    float alpha = interior * (.83 + uFocus * .1) + halo * .05;
    gl_FragColor = vec4(color, clamp(alpha, 0., .96));
  }
`;

function archCurve(x, z, inset = 0) {
  const radius = 1.06 + inset;
  return new THREE.CatmullRomCurve3([
    new THREE.Vector3(x - radius, .22, z),
    new THREE.Vector3(x - radius, 1.55, z),
    new THREE.Vector3(x - radius * .87, 2.42, z),
    new THREE.Vector3(x - radius * .50, 3.03, z),
    new THREE.Vector3(x, 3.18 + inset, z),
    new THREE.Vector3(x + radius * .50, 3.03, z),
    new THREE.Vector3(x + radius * .87, 2.42, z),
    new THREE.Vector3(x + radius, 1.55, z),
    new THREE.Vector3(x + radius, .22, z),
  ], false, 'centripetal');
}

export function mountObservatory(container, onSelect) {
  if (!window.WebGLRenderingContext) throw new Error('WebGL no disponible');
  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const narrow = window.matchMedia('(max-width: 720px)').matches;
  const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: false, powerPreference: 'default' });
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, narrow ? 1.15 : 1.6));
  renderer.outputColorSpace = THREE.SRGBColorSpace;
  renderer.toneMapping = THREE.ACESFilmicToneMapping;
  renderer.toneMappingExposure = 1.22;
  renderer.setClearColor(0x070d18);
  renderer.domElement.setAttribute('aria-hidden', 'true');
  container.appendChild(renderer.domElement);

  const scene = new THREE.Scene();
  scene.background = new THREE.Color(0x070d18);
  scene.fog = new THREE.FogExp2(0x070d18, .035);
  const camera = new THREE.PerspectiveCamera(43, 1, .1, 95);
  camera.position.set(0, 4.7, 12.7);
  camera.lookAt(0, 1.4, 0);
  scene.add(new THREE.HemisphereLight(0x9bb7da, 0x15121b, 2.2));
  const key = new THREE.DirectionalLight(0xd9e5ff, 2.0);
  key.position.set(-5, 10, 8);
  scene.add(key);

  const darkMetal = new THREE.MeshStandardMaterial({color:0x19212f, metalness:.86, roughness:.27});
  const blackStone = new THREE.MeshStandardMaterial({color:0x111b27, metalness:.43, roughness:.62});
  const trims = new THREE.MeshStandardMaterial({color:0x7a817f, metalness:.95, roughness:.23});
  const platform = new THREE.Mesh(new THREE.CylinderGeometry(7.7, 8.5, .38, 128), blackStone);
  platform.position.y = -.42;
  scene.add(platform);
  const dais = new THREE.Mesh(new THREE.CylinderGeometry(6.65, 6.7, .075, 128), darkMetal);
  dais.position.y = -.19;
  scene.add(dais);
  for (const radius of [6.25, 7.55]) {
    const ring = new THREE.Mesh(new THREE.TorusGeometry(radius, .014, 8, 192), trims);
    ring.rotation.x = -Math.PI / 2;
    ring.position.y = -.13;
    scene.add(ring);
  }
  const coords = [-3.55, 0, 3.55];
  const interactive = [];
  const portals = [];
  WORLDS.forEach((world, i) => {
    const x = coords[i], z = i === 1 ? -.35 : -.72;
    const tint = new THREE.Color(world.tone);
    const group = new THREE.Group();
    scene.add(group);
    const pedestal = new THREE.Mesh(new THREE.CylinderGeometry(1.44, 1.62, .19, 96), darkMetal);
    pedestal.position.set(x, -.06, z);
    group.add(pedestal);
    const pedestalRim = new THREE.Mesh(
      new THREE.TorusGeometry(1.43, .021, 8, 100),
      new THREE.MeshBasicMaterial({ color: tint, transparent: true, opacity: .39 })
    );
    pedestalRim.rotation.x = -Math.PI / 2;
    pedestalRim.position.set(x, .035, z);
    group.add(pedestalRim);
    for (const [offset, radius, material] of [
      [-.11, .11, darkMetal],
      [-.16, .022, trims],
      [-.20, .012, new THREE.MeshBasicMaterial({color: tint, transparent:true,opacity:.78})],
    ]) {
      const arch = new THREE.Mesh(new THREE.TubeGeometry(archCurve(x,z + offset,radius === .11 ? .07 : 0), 144, radius, 10, false), material);
      group.add(arch);
    }
    const material = new THREE.ShaderMaterial({
      vertexShader: PORTAL_VERTEX,
      fragmentShader: PORTAL_FRAGMENT,
      uniforms: { uTime:{value:0}, uFocus:{value: i === 0 ? 1 : 0}, uTint:{value:tint} },
      transparent: true, side: THREE.DoubleSide, depthWrite: false,
    });
    const glass = new THREE.Mesh(new THREE.PlaneGeometry(1.96, 2.83), material);
    glass.position.set(x, 1.68, z - .14);
    glass.userData.worldId = world.id;
    group.add(glass);
    interactive.push(glass);
    const light = new THREE.PointLight(tint, 10, 5.5, 2);
    light.position.set(x, 2.3, z + .8);
    group.add(light);
    portals.push({ world, glass, material, rim: pedestalRim, light, group });
  });

  // A finite instanced stellar canopy: one draw call, no heavyweight skybox.
  const count = narrow ? 480 : 1100;
  const stars = new Float32Array(count * 3);
  let seed = 132417;
  const random = () => {
    seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
    return seed / 4294967296;
  };
  for (let i = 0; i < count; i++) {
    const angle = random() * Math.PI * 2;
    const distance = 19 + random() * 47;
    stars[i * 3] = Math.cos(angle) * distance;
    stars[i * 3 + 1] = 3 + random() * 34;
    stars[i * 3 + 2] = -12 + Math.sin(angle) * distance;
  }
  const starGeometry = new THREE.BufferGeometry();
  starGeometry.setAttribute('position', new THREE.BufferAttribute(stars, 3));
  const starPoints = new THREE.Points(starGeometry, new THREE.PointsMaterial({
    color: 0xc0d3e8, size: .085, transparent: true, opacity: .7, sizeAttenuation: true,
  }));
  scene.add(starPoints);

  let focus = 'chess', frame = 0, disposed = false;
  let pointerDown = null, yaw = 0, desiredYaw = 0;
  const raycaster = new THREE.Raycaster();
  const pointer = new THREE.Vector2();
  function resize() {
    const {width, height} = container.getBoundingClientRect();
    camera.aspect = Math.max(1, width) / Math.max(1, height);
    camera.updateProjectionMatrix();
    renderer.setSize(Math.max(1, width), Math.max(1, height), false);
  }
  const observer = new ResizeObserver(resize);
  observer.observe(container);
  resize();
  const clock = new THREE.Clock();
  function render() {
    if (disposed) return;
    if (document.visibilityState === 'visible') {
      const time = reduceMotion ? 0 : clock.getElapsedTime();
      yaw += (desiredYaw - yaw) * .04;
      camera.position.x = Math.sin(yaw) * 2.0;
      camera.lookAt(0, 1.46, 0);
      portals.forEach(({world, material, rim, light}) => {
        const active = focus === world.id ? 1 : 0;
        material.uniforms.uTime.value = time;
        material.uniforms.uFocus.value += (active - material.uniforms.uFocus.value) * .065;
        rim.material.opacity = .28 + material.uniforms.uFocus.value * .5;
        light.intensity = 4 + material.uniforms.uFocus.value * 9;
      });
      renderer.render(scene, camera);
    }
    if (!reduceMotion) frame = requestAnimationFrame(render);
  }
  render();
  function onVisibility() {
    if (reduceMotion && document.visibilityState === 'visible') render();
  }
  document.addEventListener('visibilitychange', onVisibility);
  function hit(event) {
    const bounds = renderer.domElement.getBoundingClientRect();
    pointer.set(((event.clientX - bounds.left) / bounds.width) * 2 - 1,
                -((event.clientY - bounds.top) / bounds.height) * 2 + 1);
    raycaster.setFromCamera(pointer, camera);
    return raycaster.intersectObjects(interactive, false)[0]?.object.userData.worldId ?? null;
  }
  function onPointerDown(event) { pointerDown = {x:event.clientX,y:event.clientY}; }
  function onPointerMove(event) {
    renderer.domElement.style.cursor = hit(event) ? 'pointer' : 'grab';
    if (pointerDown && event.buttons === 1 && !reduceMotion) {
      desiredYaw = THREE.MathUtils.clamp(desiredYaw + (event.clientX - pointerDown.x) * .0015, -.33, .33);
      pointerDown = {x:event.clientX,y:event.clientY};
    }
  }
  function onPointerUp(event) {
    if (pointerDown && Math.abs(pointerDown.x - event.clientX) < 7 && Math.abs(pointerDown.y - event.clientY) < 7) {
      const id = hit(event);
      if (id) onSelect(id);
    }
    pointerDown = null;
  }
  renderer.domElement.addEventListener('pointerdown', onPointerDown);
  renderer.domElement.addEventListener('pointermove', onPointerMove);
  renderer.domElement.addEventListener('pointerup', onPointerUp);
  renderer.domElement.addEventListener('pointerleave', () => { pointerDown = null; });
  return {
    focusWorld(id) { focus = id; if (reduceMotion) render(); },
    destroy() {
      disposed = true;
      cancelAnimationFrame(frame);
      observer.disconnect();
      document.removeEventListener('visibilitychange', onVisibility);
      scene.traverse(obj => {
        obj.geometry?.dispose();
        if (Array.isArray(obj.material)) obj.material.forEach(m => m.dispose());
        else obj.material?.dispose();
      });
      renderer.dispose();
      renderer.domElement.remove();
    },
  };
}
