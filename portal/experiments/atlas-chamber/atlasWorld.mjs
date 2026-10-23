import * as THREE from 'three';

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
  scene.fog=new THREE.FogExp2(0x0a0d14,.036);
  const camera=new THREE.PerspectiveCamera(mobile?43:39,1,.1,90);
  const root=new THREE.Group();
  root.position.x=mobile ? 0 : 1.55;
  scene.add(root);
  const stone=new THREE.MeshStandardMaterial({color:0x27313a,roughness:.94,metalness:.03});
  const darkStone=new THREE.MeshStandardMaterial({color:0x141c26,roughness:.85});
  const wood=new THREE.MeshStandardMaterial({color:0x39251d,roughness:.7});
  const woodRim=new THREE.MeshStandardMaterial({color:0x523627,roughness:.48});
  const brass=new THREE.MeshStandardMaterial({color:0xb88b4d,metalness:.8,roughness:.27});
  const tarnished=new THREE.MeshStandardMaterial({color:0x55452e,metalness:.73,roughness:.44});
  const ivory=new THREE.MeshStandardMaterial({color:0xd1bea0,roughness:.36,metalness:.05});
  const obsidian=new THREE.MeshStandardMaterial({color:0x243341,roughness:.27,metalness:.22});
  const moonGlass=new THREE.MeshBasicMaterial({color:0x648bad,transparent:true,opacity:.30,depthWrite:false});
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
  scene.add(new THREE.HemisphereLight(0x718fac,0x1d1210,1.6));
  const moon=new THREE.DirectionalLight(0x8dbce8,2.4);
  moon.position.set(-4,8,-2);scene.add(moon);
  const lamp=new THREE.PointLight(0xf2aa58,32,9,2);
  lamp.position.set(4,3.2,1.6);root.add(lamp);
  const key=new THREE.PointLight(0xe7c29a,13,7,2);
  key.position.set(-2,4,3);root.add(key);

  // Room, with proper depth rather than an infinite portal-gallery backdrop.
  box(15,8,.55,stone,0,3,-5.35);
  box(.65,8,9,darkStone,-6.8,3,-.7);
  box(.65,8,9,darkStone,6.8,3,-.7);
  box(15,.35,9,wood,-0,6,-1.0);
  box(15,.32,13,stone,0,-.50,0);
  for(const x of [-5.2,-2.3,2.3,5.2]) {
    box(.30,6,.48,darkStone,x,3,-4.91);
    box(.075,6,.08,tarnished,x+.15,3,-4.55);
    box(.65,.22,.58,stone,x,5.72,-4.81);
  }
  for(let i=0;i<10;i++) {
    box(13.5,.018,.018,tarnished,0,.55+i*.55,-5.045);
  }
  // One moonlit lancet window, split by sculpted iron mullions.
  const windowShape=new THREE.Shape();
  windowShape.moveTo(-1.18,0);windowShape.lineTo(1.18,0);
  windowShape.lineTo(1.18,2.55);
  windowShape.bezierCurveTo(1.18,3.44,.60,3.92,0,4.38);
  windowShape.bezierCurveTo(-.60,3.92,-1.18,3.44,-1.18,2.55);
  windowShape.closePath();
  mesh(new THREE.ShapeGeometry(windowShape),moonGlass,0,1.10,-4.96);
  const windowBorder=new THREE.Shape();
  windowBorder.moveTo(-1.28,0);windowBorder.lineTo(-1.28,2.52);
  windowBorder.bezierCurveTo(-1.28,3.56,-.65,4.12,0,4.58);
  windowBorder.bezierCurveTo(.65,4.12,1.28,3.56,1.28,2.52);
  windowBorder.lineTo(1.28,0);
  // Extruded U-shaped frame follows the window without an opaque middle.
  const pts=windowBorder.getPoints(24).map(v=>new THREE.Vector3(v.x,v.y+1.10,-4.82));
  mesh(new THREE.TubeGeometry(new THREE.CatmullRomCurve3(pts),80,.080,7,false),tarnished);
  rod(.038,3.0,tarnished,0,2.6,-4.79);
  box(2.35,.07,.09,tarnished,0,3.15,-4.77);
  const moonDisc=mesh(new THREE.SphereGeometry(.72,28,16),
    new THREE.MeshBasicMaterial({color:0x91acc5}),.05,4.35,-5.01);
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

  // Miniature hand-turned chessmen. A single hero knight anchors the story.
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
  const knightShape=new THREE.Shape();
  knightShape.moveTo(-.20,0);
  knightShape.lineTo(.20,0);
  knightShape.lineTo(.13,.20);
  knightShape.lineTo(.07,.33);
  knightShape.lineTo(.21,.40);
  knightShape.lineTo(.26,.51);
  knightShape.lineTo(.17,.61);
  knightShape.lineTo(.02,.63);
  knightShape.lineTo(-.095,.76);
  knightShape.lineTo(-.16,.75);
  knightShape.lineTo(-.18,.54);
  knightShape.lineTo(-.13,.36);
  knightShape.lineTo(-.20,0);
  const knight=new THREE.Group();
  knight.position.set(-.60,1.18,1.24);
  root.add(knight);
  mesh(new THREE.CylinderGeometry(.25,.31,.08,24),ivory,0,.04,0,knight);
  mesh(new THREE.ExtrudeGeometry(knightShape,{depth:.17,bevelEnabled:true,bevelSize:.024,bevelThickness:.035,bevelSegments:2}),ivory,0,.10,-.09,knight);
  mesh(new THREE.SphereGeometry(.019,10,8),obsidian,.14,.60,.10,knight);
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
  mesh(new THREE.ConeGeometry(.50,.57,32,1,true),tarnished,2.52,2.20,1.65);
  mesh(new THREE.SphereGeometry(.19,20,12),
    new THREE.MeshBasicMaterial({color:0xe9a264}),2.52,1.96,1.65);
  // Two archival volumes and an inkwell: handmade still-life around the atlas.
  for(let i=0;i<3;i++) {
    box(.90,.105,.60,i%2?obsidian:woodRim,-2.50,1.08+i*.115,.05+i*.02);
    box(.91,.019,.61,brass,-2.50,1.14+i*.115,.05+i*.02);
  }
  rod(.15,.12,obsidian,-2.65,1.08,1.63);
  mesh(new THREE.ConeGeometry(.032,.4,9),brass,-2.65,1.38,1.63).rotation.z=-.35;

  // Cinematic, stationary art direction at rest. Moving parts are deliberately
  // sparse and stop under prefers-reduced-motion or hidden-tab conditions.
  camera.position.set(mobile?4.85:5.45,mobile?4.55:3.82,mobile?9.1:10.9);
  camera.lookAt(mobile?0:1.12,mobile?1.53:1.72,mobile ? .40 : .08);
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
    renderer.dispose();renderer.domElement.remove();
  }};
}
