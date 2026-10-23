import * as THREE from 'three';
import {makeAtlasSurfaceTexture} from './atlasSurface.mjs';
import {ATLAS_KNIGHT_ASSET} from '../../src/atlasKnightAsset.generated.mjs';

// Atlas Chamber vertical slice. One tactile chess diorama in a believable room;
// no portal panes, no borrowed game assets and no extra runtime downloads.
// Isolated from the production home and rendered only on the experiment page.
export function mountAtlasChamber(container) {
  if (!window.WebGLRenderingContext) throw new Error('WebGL unavailable');
  const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const mobile = window.matchMedia('(max-width: 720px)').matches;
  const renderer = new THREE.WebGLRenderer({antialias:true, powerPreference:'default'});
  renderer.setPixelRatio(Math.min(window.devicePixelRatio||1,mobile?1.2:1.5));
  renderer.outputColorSpace=THREE.SRGBColorSpace;
  renderer.toneMapping=THREE.ACESFilmicToneMapping;
  renderer.toneMappingExposure=1.35;
  renderer.setClearColor(0x0a0d14);
  renderer.domElement.setAttribute('aria-hidden','true');
  container.appendChild(renderer.domElement);
  const scene=new THREE.Scene();
  scene.background=new THREE.Color(0x0a0d14);
  scene.fog=new THREE.FogExp2(0x0a0d14,.021);
  const camera=new THREE.PerspectiveCamera(mobile?53:39,1,.1,90);
  const root=new THREE.Group();
  root.position.x=mobile ? 0 : 1.55;
  scene.add(root);
  const woodGrain=makeAtlasSurfaceTexture('wood');
  const stoneGrain=makeAtlasSurfaceTexture('stone');
  woodGrain.repeat.set(3,1);
  stoneGrain.repeat.set(2,2);
  const stone=new THREE.MeshStandardMaterial({color:0x8694a2,roughness:.94,metalness:.03,map:stoneGrain});
  const darkStone=new THREE.MeshStandardMaterial({color:0x29323d,roughness:.85});
  const wood=new THREE.MeshStandardMaterial({color:0x977758,roughness:.7,map:woodGrain});
  const woodRim=new THREE.MeshStandardMaterial({color:0xb28b65,roughness:.48,map:woodGrain});
  const brass=new THREE.MeshStandardMaterial({color:0xb88b4d,metalness:.8,roughness:.27});
  const tarnished=new THREE.MeshStandardMaterial({color:0x55452e,metalness:.73,roughness:.44});
  const ivory=new THREE.MeshStandardMaterial({color:0xd1bea0,roughness:.36,metalness:.05});
  const obsidian=new THREE.MeshStandardMaterial({color:0x243341,roughness:.27,metalness:.22});
  const nightSky=new THREE.MeshBasicMaterial({color:0x2d465f,side:THREE.DoubleSide,fog:false});
  const mesh=(geo,mat,x=0,y=0,z=0,parent=root)=>{
    const m=new THREE.Mesh(geo,mat);m.position.set(x,y,z);parent.add(m);return m;
  };
  const box=(w,h,d,mat,x,y,z)=>mesh(new THREE.BoxGeometry(w,h,d),mat,x,y,z);
  const rod=(r,length,mat,x,y,z,rotZ=0)=>{
    const m=mesh(new THREE.CylinderGeometry(r,r,length,12),mat,x,y,z);
    m.rotation.z=rotZ;return m;
  };
  const torus=(r,tube,mat,x,y,z,rotX=0,rotY=0,parent=root)=>{
    const m=mesh(new THREE.TorusGeometry(r,tube,8,80),mat,x,y,z,parent);
    m.rotation.set(rotX,rotY,0);return m;
  };
  // Moon and candlelight need distinct jobs: low ambient reveals form without
  // washing the walls; the actual lamp and window provide local color pools.
  scene.add(new THREE.HemisphereLight(0x839cb7,0x4d362c,1.28));
  const moon=new THREE.DirectionalLight(0x9bc8f2,2.85);
  moon.position.set(-4,8,-2);scene.add(moon);
  // The only warm point is tucked directly under the physical lamp shade.
  // Previously it floated far to the right, with a second broad warm key.
  const lampBulb=new THREE.Vector3(2.52,1.96,1.65);
  const lamp=new THREE.PointLight(0xffae65,18,7,2);
  lamp.position.copy(lampBulb).add(new THREE.Vector3(0,-.14,0));
  root.add(lamp);
  // Cool window bounce is secondary to the directional moon. No extra light.
  const windowBounce=new THREE.PointLight(0x84b8e8,9,7.8,2);
  windowBounce.position.set(0,4.12,-4.73);
  root.add(windowBounce);
  container.dataset.lightRig='moon-window-practical';

  // Room, with proper depth rather than an infinite portal-gallery backdrop.
  // Cut a genuine 55 cm deep lancet through the rear masonry. The previous
  // wall was solid behind a painted glass shape, so joints crossed the moon.
  const masonry=new THREE.Shape();
  masonry.moveTo(-7.5,-1);masonry.lineTo(7.5,-1);
  masonry.lineTo(7.5,7);masonry.lineTo(-7.5,7);masonry.closePath();
  const opening=new THREE.Path();
  opening.moveTo(-1.18,1.10);opening.lineTo(1.18,1.10);
  opening.lineTo(1.18,3.65);
  opening.bezierCurveTo(1.18,4.54,.60,5.02,0,5.48);
  opening.bezierCurveTo(-.60,5.02,-1.18,4.54,-1.18,3.65);
  opening.closePath();
  masonry.holes.push(opening);
  mesh(new THREE.ExtrudeGeometry(masonry,{
    depth:.55,steps:1,curveSegments:24,bevelEnabled:false,
  }),stone,0,0,-5.625);
  box(.65,8,9,darkStone,-6.8,3,-.7);
  box(.65,8,9,darkStone,6.8,3,-.7);
  box(15,.35,9,wood,-0,6,-1.0);
  // Recessed mortar bed with large, offset flagstones. The old single gray
  // floor slab read as a featureless plane; physical courses catch moonlight.
  box(15,.32,13,darkStone,0,-.50,0);
  const flagRows=14,flagCols=10;
  const flags=new THREE.InstancedMesh(
    new THREE.BoxGeometry(1.35,.026,.88),stone,flagRows*flagCols);
  const flagTransform=new THREE.Object3D();
  const flagTint=new THREE.Color();
  let flagIndex=0;
  for(let r=0;r<flagRows;r++)for(let c=0;c<flagCols;c++){
    // Alternate courses are offset like laid flagstone, not a dashboard grid.
    const x=(c-4.5)*1.39+(r%2)*.48;
    const z=(r-6.5)*.91;
    flagTransform.position.set(x,-.323,z);
    flagTransform.rotation.y=((r*7+c*3)%2)*Math.PI;
    flagTransform.updateMatrix();
    flags.setMatrixAt(flagIndex,flagTransform.matrix);
    const tint=.66+((r*13+c*7)%11)*.009;
    flagTint.setRGB(tint,tint*.99,tint*.97);
    flags.setColorAt(flagIndex,flagTint);
    flagIndex++;
  }
  flags.instanceMatrix.needsUpdate=true;
  flags.instanceColor.needsUpdate=true;
  root.add(flags);
  container.dataset.stoneFloor='flags-'+flagIndex;
  for(const x of [-5.2,-2.3,2.3,5.2]) {
    box(.30,6,.48,darkStone,x,3,-4.91);
    box(.075,6,.08,tarnished,x+.15,3,-4.55);
    box(.65,.22,.58,stone,x,5.72,-4.81);
  }
  // Hand-laid, lightly chiselled ashlar replaces the ten ink-dark stripes.
  // One InstancedMesh draws all the shallow stone faces; irregular alternating
  // courses catch the existing moon/lamplight without adding lights or textures.
  // Keep the real lancet opening free of any opaque stone, even at mobile angles.
  const ashlarShape=new THREE.Shape();
  ashlarShape.moveTo(-.695,-.266);
  ashlarShape.lineTo(.695,-.266);
  ashlarShape.lineTo(.695,.266);
  ashlarShape.lineTo(-.695,.266);
  ashlarShape.closePath();
  const ashlar=new THREE.InstancedMesh(
    new THREE.ExtrudeGeometry(ashlarShape,{
      depth:.026,steps:1,bevelEnabled:true,bevelSize:.022,
      bevelThickness:.010,bevelSegments:1,
    }),stone,90);
  const blockTransform=new THREE.Object3D();
  const blockTint=new THREE.Color();
  let blockCount=0;
  for(let r=0;r<9;r++)for(let c=0;c<10;c++){
    const x=(c-4.5)*1.45+(r%2?.26:-.26);
    const y=.55+r*.61;
    // The sill occupies y~1.1; above it, leave clear masonry around the
    // full-height lancet rather than painting blocks across moonlit sky.
    if(y>.88 && y<5.76 && Math.abs(x)<2.12)continue;
    blockTransform.position.set(x,y+(((r*5+c*3)%3)-1)*.007,-5.068);
    blockTransform.scale.set(.96+((r*3+c*7)%5)*.009,1,1);
    blockTransform.rotation.z=(((r*11+c*3)%5)-2)*.0016;
    blockTransform.updateMatrix();
    ashlar.setMatrixAt(blockCount,blockTransform.matrix);
    const patina=.80+((r*11+c*7)%9)*.015;
    blockTint.setRGB(patina,patina*.99,patina*.97);
    ashlar.setColorAt(blockCount,blockTint);
    blockCount++;
  }
  ashlar.count=blockCount;
  ashlar.instanceMatrix.needsUpdate=true;
  ashlar.instanceColor.needsUpdate=true;
  root.add(ashlar);
  container.dataset.masonryBlocks=String(blockCount);
  // One moonlit lancet window, split by sculpted iron mullions.
  const windowShape=new THREE.Shape();
  windowShape.moveTo(-1.18,0);windowShape.lineTo(1.18,0);
  windowShape.lineTo(1.18,2.55);
  windowShape.bezierCurveTo(1.18,3.44,.60,3.92,0,4.38);
  windowShape.bezierCurveTo(-.60,3.92,-1.18,3.44,-1.18,2.55);
  windowShape.closePath();
  // Opaque moonlit sky lives behind the opening, not on the wall surface.
  mesh(new THREE.ShapeGeometry(windowShape,24),nightSky,0,1.10,-5.89);
  const windowBorder=new THREE.Shape();
  windowBorder.moveTo(-1.28,0);windowBorder.lineTo(-1.28,2.52);
  windowBorder.bezierCurveTo(-1.28,3.56,-.65,4.12,0,4.58);
  windowBorder.bezierCurveTo(.65,4.12,1.28,3.56,1.28,2.52);
  windowBorder.lineTo(1.28,0);
  // Extruded U-shaped frame follows the window without an opaque middle.
  const reveal=windowBorder.getPoints(24).map(v=>new THREE.Vector3(v.x,v.y+1.10,-5.25));
  const front=reveal.map(p=>new THREE.Vector3(p.x,p.y,-4.83));
  mesh(new THREE.TubeGeometry(new THREE.CatmullRomCurve3(reveal),80,.145,8,false),darkStone);
  mesh(new THREE.TubeGeometry(new THREE.CatmullRomCurve3(front),80,.125,8,false),stone);
  const inlay=front.map(p=>new THREE.Vector3(p.x,p.y,-4.68));
  mesh(new THREE.TubeGeometry(new THREE.CatmullRomCurve3(inlay),80,.020,6,false),tarnished);
  box(2.82,.19,.60,stone,0,1.035,-4.89);
  box(2.55,.055,.66,tarnished,0,1.14,-4.86);
  // Sparse fixed stars are batched into one mesh, masked by the real hole.
  const starPositions=[];
  for(let i=0;i<18;i++){
    const x=-.96+(i*7%19)/18*1.92;
    const y=1.36+(i*11%23)/22*3.69;
    if(Math.hypot(x-.18,y-4.30)>.60)starPositions.push([x,y]);
  }
  const stars=new THREE.InstancedMesh(new THREE.SphereGeometry(.013,6,4),
    new THREE.MeshBasicMaterial({color:0xbcd0de}),starPositions.length);
  const starTransform=new THREE.Object3D();
  starPositions.forEach(([x,y],i)=>{
    starTransform.position.set(x,y,-5.78);
    starTransform.updateMatrix();stars.setMatrixAt(i,starTransform.matrix);
  });
  stars.instanceMatrix.needsUpdate=true;
  root.add(stars);
  const halo=mesh(new THREE.SphereGeometry(.73,24,16),
    new THREE.MeshBasicMaterial({color:0x83afcb,transparent:true,opacity:.12,depthWrite:false}),
    .18,4.30,-5.79);
  halo.scale.z=.012;
  const moonDisc=mesh(new THREE.SphereGeometry(.48,32,20),
    new THREE.MeshBasicMaterial({color:0xb8cbd8}),.18,4.30,-5.72);
  moonDisc.scale.z=.035;
  // Side shelves, books and handwritten-map-like stacked folios.
  for(const y of [1.42,2.55,3.68]) {
    box(2.05,.13,.72,woodRim,-4.35,y,-3.65);
    for(let i=0;i<8;i++){
      const height=.37+(i%4)*.12;
      const m= i%3===0?woodRim:i%3===1?obsidian:tarnished;
      const b=box(.17,height,.37,m,-5.19+i*.23,y+.07+height/2,-3.73);
      b.rotation.z=(i%5-2)*.035;
    }
  }
  for(const x of [-5.37,-3.33]){
    box(.14,3.8,.75,wood,x,2.85,-3.62);
  }
  // Six substantial structural beams give the chamber a near-field ceiling.
  for(let i=0;i<5;i++) {
    box(.19,.23,10,woodRim,-5.2+i*2.6,5.78,-.7);
  }
  // A real table: thick beveled edge, underside, carved supports.
  box(7.1,.23,4.45,woodRim,0,.82,.65);
  box(6.82,.06,4.16,wood,0,.976,.65);
  box(7.27,.055,4.53,tarnished,0,.69,.65);
  for(const x of [-3.05,3.05])for(const z of [-1.05,2.25]){
    box(.38,1.26,.38,woodRim,x,.12,z);
    box(.48,.10,.48,brass,x,.62,z);
  }
  for(const z of [-1.1,2.3]) box(6,.20,.13,wood,0,.25,z);

  // The world atlas: a recessed stone-and-brass chess study, not a flat panel.
  box(3.52,.075,3.52,brass,.0,1.075,.42);
  box(3.41,.055,3.41,darkStone,.0,1.132,.42);
  const squareG=new THREE.BoxGeometry(.399,.012,.399);
  const lightTiles=new THREE.InstancedMesh(squareG,ivory,32);
  const darkTiles=new THREE.InstancedMesh(squareG,obsidian,32);
  const dummy=new THREE.Object3D();let wi=0,bi=0;
  for(let r=0;r<8;r++)for(let c=0;c<8;c++){
    dummy.position.set((c-3.5)*.405,1.171,.42+(r-3.5)*.405);
    dummy.updateMatrix();
    ((r+c)%2===0?lightTiles:darkTiles).setMatrixAt((r+c)%2===0?wi++:bi++,dummy.matrix);
  }
  lightTiles.instanceMatrix.needsUpdate=true;
  darkTiles.instanceMatrix.needsUpdate=true;
  root.add(lightTiles,darkTiles);
  for(const v of [-1.735,1.735]) {
    box(.025,.025,3.52,brass,v,1.18,.42);
    box(3.52,.025,.025,brass,0,1.18,.42+v);
  }

  // Miniature hand-turned chessmen. One authored hero knight anchors the story.
  container.dataset.atlasKnight=ATLAS_KNIGHT_ASSET?'loading':'fallback';
  function pawn(x,z,mat,h=.29) {
    const g=new THREE.Group();g.position.set(x,1.183,z);root.add(g);
    mesh(new THREE.CylinderGeometry(.105,.13,.055,16),mat,0,.028,0,g);
    mesh(new THREE.CylinderGeometry(.056,.08,h*.53,16),mat,0,.090+h*.22,0,g);
    mesh(new THREE.SphereGeometry(.078,14,10),mat,0,h+.055,0,g);
    return g;
  }
  function crown(x,z,mat){
    const g=new THREE.Group();g.position.set(x,1.18,z);root.add(g);
    mesh(new THREE.CylinderGeometry(.17,.21,.09,24),mat,0,.055,0,g);
    mesh(new THREE.CylinderGeometry(.107,.16,.46,24),mat,0,.33,0,g);
    torus(.13,.027,brass,0,.58,0,Math.PI/2,0,g);
    mesh(new THREE.SphereGeometry(.14,20,12),mat,0,.68,0,g);
    mesh(new THREE.BoxGeometry(.05,.26,.05),brass,0,.85,0,g);
    mesh(new THREE.BoxGeometry(.19,.05,.05),brass,0,.88,0,g);
    return g;
  }
  // Curved, chiselled knight profile with a distinct muzzle and swept mane:
  // this must read as a horse silhouette, never an extrusion of square steps.
  const knightShape=new THREE.Shape();
  knightShape.moveTo(-.23,0);
  knightShape.lineTo(.21,0);
  knightShape.bezierCurveTo(.08,.12,.05,.18,.10,.31);
  knightShape.bezierCurveTo(.14,.37,.21,.39,.285,.445);
  knightShape.lineTo(.275,.508);
  knightShape.bezierCurveTo(.24,.58,.15,.595,.06,.566);
  knightShape.bezierCurveTo(.048,.66,.02,.75,-.060,.80);
  knightShape.lineTo(-.138,.78);
  knightShape.lineTo(-.122,.68);
  knightShape.bezierCurveTo(-.24,.59,-.22,.42,-.17,.30);
  knightShape.bezierCurveTo(-.12,.18,-.16,.08,-.23,0);
  const knight=new THREE.Group();
  knight.position.set(-.60,1.18,1.24);
  root.add(knight);
  // Retain the verified original as an immediate placeholder / full fallback.
  const knightFallback=new THREE.Group();
  knight.add(knightFallback);
  mesh(new THREE.CylinderGeometry(.25,.31,.08,24),ivory,0,.04,0,knightFallback);
  mesh(new THREE.ExtrudeGeometry(knightShape,{depth:.21,curveSegments:20,bevelEnabled:true,bevelSize:.026,bevelThickness:.036,bevelSegments:4}),ivory,0,.10,-.09,knightFallback);
  mesh(new THREE.SphereGeometry(.017,12,8),obsidian,.145,.61,.14,knightFallback);
  // Sculpted in Blender, loaded after the first usable frame. In reduced
  // motion, a successful load explicitly repaints before screenshot capture.
  if(ATLAS_KNIGHT_ASSET){
    import('three/addons/loaders/GLTFLoader.js').then(async({GLTFLoader})=>{
      const loaded=await new GLTFLoader().loadAsync(ATLAS_KNIGHT_ASSET);
      if(disposed){
        loaded.scene.traverse(obj=>{
          obj.geometry?.dispose();
          if(Array.isArray(obj.material))obj.material.forEach(m=>m.dispose());
          else obj.material?.dispose();
        });
        return;
      }
      knight.add(loaded.scene);
      knightFallback.visible=false;
      container.dataset.atlasKnight='loaded';
      paint();
    }).catch(error=>{
      if(disposed)return;
      console.warn('Atlas knight sculpture unavailable; preserve carved fallback.',error);
      container.dataset.atlasKnight='fallback';
      paint();
    });
  }
  crown(.64,-.99,obsidian);
  pawn(-1.2,1.24,ivory);pawn(-.17,1.24,ivory);
  pawn(.65,-.58,obsidian);pawn(1.06,-.99,obsidian);
  pawn(1.05,1.24,ivory);

  // Astronomical instrument behind the board. Brass catches existing light,
  // no neon glass portals or huge holographic HUD.
  const mechanism=new THREE.Group();
  mechanism.position.set(.0,2.58,-1.90);
  root.add(mechanism);
  function instrumentRing(r,tube,rotX,rotY){
    const m=new THREE.Mesh(new THREE.TorusGeometry(r,tube,9,110),brass);
    m.rotation.set(rotX,rotY,.03);mechanism.add(m);return m;
  }
  instrumentRing(1.32,.044,.10,.08);
  instrumentRing(1.17,.014,.21,-.12);
  const moving=instrumentRing(.94,.018,.50,1.00);
  instrumentRing(.73,.013,-.45,.48);
  mesh(new THREE.IcosahedronGeometry(.24,1),obsidian,0,0,0,mechanism);
  for(let i=0;i<12;i++){
    const angle=i*Math.PI/6;
    const spot=mesh(new THREE.SphereGeometry(i%3===0?.043:.025,8,6),
      i%3===0?ivory:brass,Math.cos(angle)*1.26,Math.sin(angle)*1.26,.03,mechanism);
    spot.scale.z=.6;
  }
  // Working brass table lamp: an amber pool, not a free-floating point light.
  box(.72,.10,.72,tarnished,2.52,1.10,1.65);
  rod(.052,1.00,brass,2.52,1.60,1.65);
  // A period-appropriate brushed-brass shade must stay readable even though
  // its bulb (correctly) lights the underside, not the outer conical shell.
  // This is surface reflectance with a tiny fixed glow, not another light.
  const brushedShade=new THREE.MeshStandardMaterial({
    color:0xc69a5b,metalness:.48,roughness:.41,
    emissive:0x68401d,emissiveIntensity:.28,
  });
  mesh(new THREE.ConeGeometry(.50,.57,32,1,true),brushedShade,2.52,2.20,1.65);
  mesh(new THREE.SphereGeometry(.19,20,12),
    new THREE.MeshBasicMaterial({color:0xffbe76}),lampBulb.x,lampBulb.y,lampBulb.z);
  // Two archival volumes and an inkwell: handmade still-life around the atlas.
  for(let i=0;i<3;i++) {
    box(.90,.105,.60,i%2?obsidian:woodRim,-2.50,1.08+i*.115,.05+i*.02);
    box(.91,.019,.61,brass,-2.50,1.14+i*.115,.05+i*.02);
  }
  rod(.15,.12,obsidian,-2.65,1.08,1.63);
  mesh(new THREE.ConeGeometry(.032,.4,9),brass,-2.65,1.38,1.63).rotation.z=-.35;

  // Cinematic, stationary art direction at rest. Moving parts are deliberately
  // sparse and stop under prefers-reduced-motion or hidden-tab conditions.
  camera.position.set(mobile?5.1:5.45,mobile?5.35:3.82,mobile?12.3:10.9);
  camera.lookAt(mobile?0:1.12,mobile?1.82:1.72,mobile ? .40 : .08);
  const observer=new ResizeObserver(()=>{
    const width=Math.max(1,container.clientWidth),height=Math.max(1,container.clientHeight);
    camera.aspect=width/height;
    camera.updateProjectionMatrix();
    renderer.setSize(width,height,false);
    paint();
  });
  let disposed=false,raf=0,last=0,elapsed=0,visible=true,ready=false;
  function paint(){
    if(disposed||!visible||document.visibilityState!=='visible')return;
    renderer.render(scene,camera);
    container.dataset.drawCalls=String(renderer.info.render.calls);
    container.dataset.triangles=String(renderer.info.render.triangles);
    if(!ready){ready=true;container.dataset.renderState='ready';}
  }
  function animate(now){
    if(disposed)return;
    if(!reduced&&visible&&document.visibilityState==='visible'&&now-last>=1000/(mobile?30:36)){
      elapsed+=Math.min((now-last)/1000,.045);
      moving.rotation.y=1.0+Math.sin(elapsed*.20)*.055;
      paint();last=now;
    }
    raf=requestAnimationFrame(animate);
  }
  const viewportObserver=new IntersectionObserver(entries=>{
    visible=entries.some(e=>e.isIntersecting);
    if(visible)paint();
  },{threshold:0});
  observer.observe(container);
  viewportObserver.observe(container);
  const onVisibility=()=>{if(document.visibilityState==='visible')paint();};
  document.addEventListener('visibilitychange',onVisibility);
  if(reduced)paint();
  else raf=requestAnimationFrame(animate);
  container.dataset.motion=reduced?'reduced':'gentle';
  return {destroy(){
    disposed=true;cancelAnimationFrame(raf);
    observer.disconnect();viewportObserver.disconnect();
    document.removeEventListener('visibilitychange',onVisibility);
    scene.traverse(object=>{
      object.geometry?.dispose();
      if(Array.isArray(object.material))object.material.forEach(m=>m.dispose());
      else object.material?.dispose();
    });
    woodGrain.dispose();stoneGrain.dispose();
    renderer.dispose();renderer.domElement.remove();
  }};
}
