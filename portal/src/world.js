import * as THREE from 'three';
import { WORLDS } from './catalog.mjs';
import { VISTA_VERTEX, VISTA_FRAGMENT } from './portalVistas.js';
import { addGalleryArchitecture } from './galleryArchitecture.js';
import { ARMILLARY_ASSET } from './armillaryAsset.generated.mjs';
import { WORLD_RELICS } from './worldRelics.generated.mjs';
import { GALLERY_FRAME_ASSET } from './galleryFrame.generated.mjs';
import { VAULT_ASSET } from './vaultAsset.generated.mjs';

// A self-contained atmospheric observatory. No borrowed Chess Studio models.
// Source-authored GLB/texture art can replace the gateways in a later art PR.

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
  camera.position.set(0, narrow ? 4.15 : 3.75, narrow ? 13.0 : 11.3);
  camera.lookAt(0, 1.4, 0);
  scene.add(new THREE.HemisphereLight(0xb4c7e0, 0x261e1a, 3.1));
  const key = new THREE.DirectionalLight(0xd9e5ff, 2.0);
  key.position.set(-5, 9, 7);
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
  const coords = [-3.22, 0, 3.22];
  const gallery = addGalleryArchitecture(scene, coords, narrow);
  container.dataset.galleryFrame = 'loading';
  container.dataset.celestialVault = VAULT_ASSET ? 'loading' : 'skipped';
  container.dataset.artAsset = narrow ? 'skipped-mobile' : 'loading';
  container.dataset.worldRelics = narrow ? 'skipped-mobile' : 'loading';
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
      vertexShader: VISTA_VERTEX,
      fragmentShader: VISTA_FRAGMENT,
      uniforms: { uTime:{value:0}, uFocus:{value: i === 0 ? 1 : 0}, uMode:{value:i}, uTint:{value:tint} },
      transparent: true, side: THREE.DoubleSide, depthWrite: false,
    });
    const glass = new THREE.Mesh(new THREE.PlaneGeometry(1.96, 2.83), material);
    glass.position.set(x, 1.68, z - .14);
    glass.userData.worldId = world.id;
    group.add(glass);
    interactive.push(glass);
    const light = new THREE.PointLight(tint, 20, 6.5, 2);
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
  let pointerDown = null, pointerStart = null, yaw = 0, desiredYaw = 0;
  let cameraShift = 0, targetShift = 0, firstFrameRendered = false;
  let lastPaint = 0, sceneTime = 0;
  // The catalog remains usable offscreen; the canvas should not burn GPU time.
  let stageInViewport = true;
  const maxFps = narrow ? 30 : 45;
  const framePeriod = 1000 / maxFps;
  const raycaster = new THREE.Raycaster();
  const pointer = new THREE.Vector2();
  const clock = new THREE.Clock();

  function resize() {
    const {width, height} = container.getBoundingClientRect();
    camera.aspect = Math.max(1, width) / Math.max(1, height);
    camera.updateProjectionMatrix();
    renderer.setSize(Math.max(1, width), Math.max(1, height), false);
    // Resize clears a canvas; reduced-motion mode has no continuous redraw.
    if (reduceMotion && firstFrameRendered) paint();
  }
  const observer = new ResizeObserver(resize);
  observer.observe(container);
  resize();

  // Painting and frame scheduling are intentionally separate: rAF passes a
  // timestamp, NOT a Boolean "force". A hidden tab must never force a draw.
  function paint() {
    if (disposed || !stageInViewport || document.visibilityState !== 'visible') return;
    const time = reduceMotion ? 0 : (sceneTime += Math.min(.06, clock.getDelta()));
    yaw = reduceMotion ? desiredYaw : yaw + (desiredYaw - yaw) * .055;
    cameraShift = reduceMotion ? targetShift : cameraShift + (targetShift - cameraShift) * .055;
    camera.position.x = Math.sin(yaw) * 2 + cameraShift;
    camera.lookAt(cameraShift * .38,1.46,0);
    portals.forEach(({world, material, rim, light}) => {
      const active = focus === world.id ? 1 : 0;
      material.uniforms.uTime.value = time;
      const level = material.uniforms.uFocus.value;
      material.uniforms.uFocus.value = reduceMotion ? active : level + (active - level) * .09;
      rim.material.opacity = .28 + material.uniforms.uFocus.value * .5;
      light.intensity = 4 + material.uniforms.uFocus.value * 9;
    });
    renderer.render(scene,camera);
    if (import.meta.env.DEV) {
      container.dataset.drawCalls = String(renderer.info.render.calls);
      container.dataset.triangles = String(renderer.info.render.triangles);
      container.dataset.renderBudget = String(maxFps);
      container.dataset.focusWorld = focus;
      container.dataset.focusBlend = String(portals.find(p=>p.world.id===focus)?.material.uniforms.uFocus.value ?? 0);
    }
    firstFrameRendered = true;
  }
  function onFrame(now) {
    frame = 0;
    if (disposed || !stageInViewport || document.visibilityState !== 'visible') return;
    if (now - lastPaint >= framePeriod) {
      lastPaint = now;
      paint();
    }
    frame = requestAnimationFrame(onFrame);
  }
  function syncRendering() {
    if (disposed) return;
    if (!stageInViewport || document.visibilityState !== 'visible') {
      cancelAnimationFrame(frame);
      frame = 0;
      container.dataset.renderState = stageInViewport ? 'background' : 'offscreen';
      return;
    }
    // Resume with one fresh frame, including when reduced-motion is enabled.
    // Consume elapsed clock time so an offscreen interval never animates ahead.
    clock.getDelta();
    lastPaint = 0;
    paint();
    container.dataset.renderState = reduceMotion ? 'still' : 'running';
    if (!reduceMotion && !frame) frame = requestAnimationFrame(onFrame);
  }
  const viewportObserver = typeof IntersectionObserver === 'function'
    ? new IntersectionObserver(entries => {
      stageInViewport = entries.some(entry => entry.isIntersecting);
      syncRendering();
    }, { threshold: 0 })
    : null;
  viewportObserver?.observe(container);
  syncRendering();
  document.addEventListener('visibilitychange', syncRendering);

  function hit(event) {
    const bounds = renderer.domElement.getBoundingClientRect();
    pointer.set(((event.clientX - bounds.left) / bounds.width) * 2 - 1,
                -((event.clientY - bounds.top) / bounds.height) * 2 + 1);
    raycaster.setFromCamera(pointer, camera);
    return raycaster.intersectObjects(interactive, false)[0]?.object.userData.worldId ?? null;
  }
  function onPointerDown(event) { pointerStart = {x:event.clientX,y:event.clientY}; pointerDown = pointerStart; }
  function onPointerMove(event) {
    renderer.domElement.style.cursor = hit(event) ? 'pointer' : 'grab';
    if (pointerDown && event.buttons === 1 && !reduceMotion) {
      desiredYaw = THREE.MathUtils.clamp(desiredYaw + (event.clientX - pointerDown.x) * .0015, -.33, .33);
      pointerDown = {x:event.clientX,y:event.clientY};
    }
  }
  function onPointerUp(event) {
    if (pointerStart && Math.abs(pointerStart.x - event.clientX) < 7 && Math.abs(pointerStart.y - event.clientY) < 7) {
      const id = hit(event);
      if (id) onSelect(id);
    }
    pointerDown = null;
    pointerStart = null;
  }
  // Authored static gallery geometry: 3 batched PBR meshes replace dozens
  // of procedural arches, columns and ornaments in the normal render path.
  // A download or parse failure falls back to the previous faithful masonry.
  import('three/addons/loaders/GLTFLoader.js')
    .then(async ({GLTFLoader}) => {
      const asset=await new GLTFLoader().loadAsync(GALLERY_FRAME_ASSET);
      if(disposed)return;
      scene.add(asset.scene);
      container.dataset.galleryFrame='loaded';
      paint();
    })
    .catch(error=>{
      if(disposed)return;
      console.warn('ShadowOps gallery frame unavailable; using fallback masonry.',error);
      gallery.activateFallback();
      container.dataset.galleryFrame='fallback';
      paint();
    });

  // Blender-authored environment asset. The game catalog and portal hit
  // targets never depend on a DCC model fetching or parsing successfully.
  if(VAULT_ASSET) {
    import('three/addons/loaders/GLTFLoader.js').then(async ({GLTFLoader})=>{
      const data=await new GLTFLoader().loadAsync(VAULT_ASSET);
      if(disposed)return;
      // Spatial contract: an exporter may succeed but rotate Blender's Z-up
      // scene into the wrong Three.js axes, leaving invisible architecture.
      // The gallery's opaque rear wall is at z=-1.85. Bring the vaulted
      // stonework in front of it; otherwise a valid GLB is completely hidden.
      // The same Blender asset now contains an inset forecourt at floor level.
      data.scene.position.z = 1.58;
      const bounds=new THREE.Box3().setFromObject(data.scene);
      if(bounds.isEmpty() || bounds.min.y < -.3 || bounds.min.y > -.05 ||
         bounds.max.y > 6.6 || bounds.max.y < 5.0 ||
         bounds.min.z < -1.8 || bounds.max.z < 4.0 || bounds.max.z > 5.5 ||
         bounds.min.x < -7 || bounds.max.x > 7) {
        throw new Error('Vault GLB has invalid gallery bounds: '+bounds.min.toArray()+' / '+bounds.max.toArray());
      }
      scene.add(data.scene);
      container.dataset.celestialVault='loaded';
      paint();
    }).catch(error=>{
      if(disposed)return;
      console.warn('Optional observatory vault unavailable; gallery remains usable.',error);
      container.dataset.celestialVault='fallback';
    });
  }

  // First independent art asset. Loads after the interactive gallery mounts.
  // Two copies share one GLB model and GPU geometry; no extra mobile cost.
  if (!narrow) {
    import('three/addons/loaders/GLTFLoader.js').then(async ({ GLTFLoader }) => {
      const gltf = await new GLTFLoader().loadAsync(ARMILLARY_ASSET);
      if (disposed) return;
      for (const x of [-4.82,4.82]) {
        const art = gltf.scene.clone(true);
        art.scale.setScalar(.82);
        art.position.set(x,-.40,.24);
        art.rotation.y = x < 0 ? -.28 : .28;
        scene.add(art);
      }
      container.dataset.artAsset = 'loaded';
      paint();
    }).catch(error => {
      if (disposed) return;
      console.warn('ShadowOps optional GLB unavailable; keeping playable portals.',error);
      container.dataset.artAsset = 'failed';
    });
  }
  // Independent art relics mount over each arch, never over the actual
  // clickable portal panes. Mobile avoids the extra GLB payload and draw calls.
  if (!narrow) {
    import('three/addons/loaders/GLTFLoader.js').then(async ({GLTFLoader}) => {
      const loader=new GLTFLoader();
      const entries=['chess','chronicles','star'];
      const results=await Promise.allSettled(entries.map(id=>loader.loadAsync(WORLD_RELICS[id].url)));
      if (disposed) return;
      const mounts=[];
      results.forEach((result,i)=>{
        if(result.status!=='fulfilled')return;
        const crest=result.value.scene;
        crest.position.set(coords[i],3.59,.16);
        crest.scale.setScalar(.47);
        scene.add(crest);
        mounts.push(entries[i]);
      });
      container.dataset.worldRelics = mounts.length === 3 ? 'loaded' : 'partial';
      paint();
    }).catch(error => {
      if(disposed)return;
      console.warn('ShadowOps optional relics unavailable',error);
      container.dataset.worldRelics='failed';
    });
  }
  renderer.domElement.addEventListener('pointerdown', onPointerDown);
  renderer.domElement.addEventListener('pointermove', onPointerMove);
  renderer.domElement.addEventListener('pointerup', onPointerUp);
  renderer.domElement.addEventListener('pointerleave', () => { pointerDown = null; pointerStart = null; });
  return {
    focusWorld(id, moveCamera = true) {
      const index = WORLDS.findIndex(world => world.id === id);
      if (index < 0) return;
      focus = id;
      // Keep all three doors in frame: cinematography, not camera hijacking.
      targetShift = moveCamera ? (index - 1) * .32 : 0;
      if (reduceMotion) paint();
    },
    destroy() {
      disposed = true;
      cancelAnimationFrame(frame);
      observer.disconnect();
      viewportObserver?.disconnect();
      document.removeEventListener('visibilitychange', syncRendering);
      scene.traverse(obj => {
        obj.geometry?.dispose();
        if (Array.isArray(obj.material)) obj.material.forEach(m => m.dispose());
        else obj.material?.dispose();
      });
      gallery.dispose();
      renderer.dispose();
      renderer.domElement.remove();
    },
  };
}
