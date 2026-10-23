import * as THREE from 'three';
import {RoundedBoxGeometry} from 'three/addons/geometries/RoundedBoxGeometry.js';
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
  // The archivist's oak library. The original 24 independent dark cubes
  // read as featureless blocks; actual bound volumes need distinct cloth and
  // leather faces, gilt head/tail bands and a carved timber surround.
  // Bindings are InstancedMesh: 24 spines + 48 gilt lines in four draw calls.
  const oxblood=new THREE.MeshStandardMaterial({color:0x63403b,roughness:.84});
  const indigoCloth=new THREE.MeshStandardMaterial({color:0x435267,roughness:.93});
  const oldVellum=new THREE.MeshStandardMaterial({color:0xb49a76,roughness:.91});
  const gilt=new THREE.MeshStandardMaterial({color:0xc1a36b,metalness:.64,roughness:.42});
  const folioColors=[oxblood,indigoCloth,oldVellum];
  const bindingGeometry=new THREE.BoxGeometry(1,1,1);
  const folios=folioColors.map(material=>
    new THREE.InstancedMesh(bindingGeometry,material,8));
  const titleBands=new THREE.InstancedMesh(
    new THREE.BoxGeometry(1,1,1),gilt,48);
  const bindingTransform=new THREE.Object3D();
  const bandsTransform=new THREE.Object3D();
  const bindingIndices=[0,0,0];
  let bandCount=0;
  // Recessed oak backing gives the book spines real room depth.
  box(2.10,3.76,.11,wood,-4.35,2.78,-4.03);
  for(const [shelf,y] of [1.42,2.55,3.68].entries()){
    box(2.05,.13,.72,woodRim,-4.35,y,-3.65);
    for(let i=0;i<8;i++){
      const height=.43+((i*3+shelf*5)%5)*.075;
      const width=.155+((i+shelf)%3)*.015;
      const x=-5.18+i*.23;
      const leaning=(((i*7+shelf*3)%5)-2)*.022;
      bindingTransform.position.set(x,y+.07+height/2,-3.71);
      bindingTransform.scale.set(width,height,.40);
      bindingTransform.rotation.set(0,0,leaning);
      bindingTransform.updateMatrix();
      const colorIndex=(i+shelf*2)%folioColors.length;
      folios[colorIndex].setMatrixAt(bindingIndices[colorIndex]++,bindingTransform.matrix);
      for(const fraction of [.18,.83]){
        bandsTransform.position.set(x,y+.07+height*fraction,-3.504);
        bandsTransform.scale.set(width*.78,.015,.012);
        bandsTransform.rotation.set(0,0,leaning);
        bandsTransform.updateMatrix();
        titleBands.setMatrixAt(bandCount++,bandsTransform.matrix);
      }
    }
  }
  folios.forEach((folio,i)=>{
    folio.count=bindingIndices[i];
    folio.instanceMatrix.needsUpdate=true;
    root.add(folio);
  });
  titleBands.instanceMatrix.needsUpdate=true;
  root.add(titleBands);
  for(const x of [-5.37,-3.33]){
    box(.14,3.8,.75,wood,x,2.85,-3.62);
    box(.22,.14,.81,woodRim,x,4.70,-3.61);
  }
  // Curved carved crest: subtle Gothic top, not a flat IKEA shelf.
  const bookCrest=new THREE.Shape();
  bookCrest.moveTo(-1.08,0);bookCrest.lineTo(1.08,0);
  bookCrest.lineTo(.98,.15);
  bookCrest.bezierCurveTo(.58,.16,.23,.43,0,.50);
  bookCrest.bezierCurveTo(-.23,.43,-.58,.16,-.98,.15);
  bookCrest.closePath();
  mesh(new THREE.ExtrudeGeometry(bookCrest,{
    depth:.11,steps:1,curveSegments:12,bevelEnabled:true,
    bevelSize:.018,bevelThickness:.012,bevelSegments:1,
  }),woodRim,-4.35,4.58,-3.43);
  container.dataset.archiveVolumes=String(bindingIndices.reduce((a,b)=>a+b,0));
  // The ceiling is not a single plank: cross-rafters interlock with the
  // existing longitudinal timbers to read as deep, restrained oak coffers.
  // One batched mesh adds all four transoms without extra downloads/lights.
  for(let i=0;i<5;i++){
    box(.19,.23,10,woodRim,-5.2+i*2.6,5.78,-.7);
  }
  const ceilingRafters=new THREE.InstancedMesh(
    new RoundedBoxGeometry(13.0,.24,.29,2,.040),wood,4);
  const rafterTransform=new THREE.Object3D();
  for(let i=0;i<4;i++){
    rafterTransform.position.set(0,5.66,-3.93+i*2.34);
    rafterTransform.updateMatrix();
    ceilingRafters.setMatrixAt(i,rafterTransform.matrix);
  }
  ceilingRafters.instanceMatrix.needsUpdate=true;
  root.add(ceilingRafters);
  container.dataset.ceilingRafters='4';

  // The visible right wing of the rear wall needs one believable engaged
  // relieving arch, not a repeated arcade hidden behind the editorial copy.
  // Its masonry sits proud of the existing ashlar yet leaves the central
  // moonlit lancet completely open. No additional virtual door/window.
  const buttressX=[2.90,5.45];
  const buttressGeo=new RoundedBoxGeometry(.29,3.18,.28,2,.035);
  const buttresses=new THREE.InstancedMesh(buttressGeo,stone,2);
  const buttressCaps=new THREE.InstancedMesh(
    new RoundedBoxGeometry(.48,.19,.36,2,.033),stone,2);
  const pierTransform=new THREE.Object3D();
  for(let i=0;i<2;i++){
    pierTransform.position.set(buttressX[i],2.11,-4.91);
    pierTransform.updateMatrix();
    buttresses.setMatrixAt(i,pierTransform.matrix);
    pierTransform.position.set(buttressX[i],3.75,-4.87);
    pierTransform.updateMatrix();
    buttressCaps.setMatrixAt(i,pierTransform.matrix);
  }
  buttresses.instanceMatrix.needsUpdate=true;
  buttressCaps.instanceMatrix.needsUpdate=true;
  root.add(buttresses,buttressCaps);
  const archSpringY=3.79,archApexY=4.95,archFront=-4.79;
  const archShoulder=new THREE.Vector3(4.175,archApexY,archFront);
  const leftHalf=new THREE.CubicBezierCurve3(
    new THREE.Vector3(buttressX[0],archSpringY,archFront),
    new THREE.Vector3(3.02,4.39,archFront),
    new THREE.Vector3(3.86,4.81,archFront),
    archShoulder,
  );
  const rightHalf=new THREE.CubicBezierCurve3(
    archShoulder,
    new THREE.Vector3(4.49,4.81,archFront),
    new THREE.Vector3(5.33,4.39,archFront),
    new THREE.Vector3(buttressX[1],archSpringY,archFront),
  );
  for(const half of [leftHalf,rightHalf])
    mesh(new THREE.TubeGeometry(half,24,.097,8,false),stone);
  container.dataset.rearButtress='right-ashlar-arch';
  // An oak cabinetmaker's chess table: eased edges replace the old square
  // slabs; a narrow carved apron hangs under the lip facing the viewer.
  // Both bevels are local geometry, not extra materials or texture requests.
  const tableOak=new THREE.MeshStandardMaterial({
    color:0xb28b65,roughness:.69,map:woodGrain,
  });
  mesh(new RoundedBoxGeometry(7.1,.23,4.45,3,.052),tableOak,0,.82,.65);
  mesh(new RoundedBoxGeometry(6.82,.06,4.16,2,.017),wood,0,.976,.65);
  box(7.27,.055,4.53,tarnished,0,.69,.65);
  // Keep the deep apron underneath the actual playing surface; it cannot
  // obscure any pieces or interact with the king/knight geometry.
  box(6.62,.31,.16,tableOak,0,.535,2.71);
  const carveMaterial=new THREE.MeshStandardMaterial({
    color:0x936b49,roughness:.86,map:woodGrain,
  });
  const gothicPanel=new THREE.Shape();
  gothicPanel.moveTo(-.245,-.115);
  gothicPanel.lineTo(.245,-.115);
  gothicPanel.lineTo(.245,.015);
  gothicPanel.quadraticCurveTo(.225,.12,0,.148);
  gothicPanel.quadraticCurveTo(-.225,.12,-.245,.015);
  gothicPanel.closePath();
  const carvedPanels=new THREE.InstancedMesh(
    new THREE.ExtrudeGeometry(gothicPanel,{
      depth:.013,steps:1,curveSegments:8,
      bevelEnabled:true,bevelThickness:.006,
      bevelSize:.007,bevelSegments:1,
    }),carveMaterial,8);
  const carvingTransform=new THREE.Object3D();
  for(let i=0;i<8;i++){
    carvingTransform.position.set((i-3.5)*.78,.535,2.803);
    carvingTransform.updateMatrix();
    carvedPanels.setMatrixAt(i,carvingTransform.matrix);
  }
  carvedPanels.instanceMatrix.needsUpdate=true;
  root.add(carvedPanels);
  // Four chamfered legs keep the original footprint and support locations.
  const legGeometry=new RoundedBoxGeometry(.38,1.26,.38,2,.065);
  for(const x of [-3.05,3.05])for(const z of [-1.05,2.25]){
    mesh(legGeometry,tableOak,x,.12,z);
    box(.48,.10,.48,brass,x,.62,z);
  }
  for(const z of [-1.1,2.3]) box(6,.20,.13,wood,0,.25,z);
  container.dataset.carvedTable='apron-8';

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
  // Miniature chessmen are turned in one continuous profile, rather than
  // stacked cylindrical placeholders. Each is a single draw call for its
  // body; the king retains his discreet brass cross and collar.
  const lathe=(pairs,segments=20)=>new THREE.LatheGeometry(
    pairs.map(([r,y])=>new THREE.Vector2(r,y)),segments);
  const pawnProfile=lathe([
    [0,0],[.113,0],[.129,.012],[.129,.038],[.112,.049],
    [.089,.057],[.083,.070],[.061,.095],[.056,.127],
    [.048,.165],[.054,.208],[.070,.247],[.074,.260],
    [.057,.272],[.047,.282],[.069,.293],[.078,.319],
    [.079,.345],[.067,.374],[.047,.399],[.023,.418],[0,.424],
  ],18);
  const crownProfile=lathe([
    [0,0],[.19,0],[.207,.018],[.207,.065],
    [.181,.092],[.155,.104],[.147,.124],[.135,.158],
    [.116,.203],[.108,.265],[.103,.368],[.109,.454],
    [.136,.512],[.151,.544],[.143,.571],[.118,.587],
    [.137,.604],[.149,.645],[.136,.686],[.102,.715],
    [.062,.734],[0,.742],
  ],22);
  const pawn=(x,z,mat)=>{
    mesh(pawnProfile,mat,x,1.183,z);
  };
  const crown=(x,z,mat)=>{
    const g=new THREE.Group();g.position.set(x,1.18,z);root.add(g);
    mesh(crownProfile,mat,0,0,0,g);
    torus(.139,.013,brass,0,.57,0,Math.PI/2,0,g);
    mesh(new THREE.BoxGeometry(.05,.23,.05),brass,0,.82,0,g);
    mesh(new THREE.BoxGeometry(.18,.045,.055),brass,0,.86,0,g);
  };
  container.dataset.turnedChessmen='5-pawns-1-crown';
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
  // The engraved hour studs share two meshes instead of twelve individual
  // draw calls, leaving room for a physically grounded instrument mount.
  const hourMarks=new THREE.InstancedMesh(
    new THREE.SphereGeometry(.025,8,6),brass,8);
  const cardinalMarks=new THREE.InstancedMesh(
    new THREE.SphereGeometry(.043,8,6),ivory,4);
  const markTransform=new THREE.Object3D();
  let hours=0,cardinals=0;
  for(let i=0;i<12;i++){
    const angle=i*Math.PI/6;
    markTransform.position.set(Math.cos(angle)*1.26,Math.sin(angle)*1.26,.03);
    markTransform.scale.set(1,1,.6);
    markTransform.updateMatrix();
    const cardinal=i%3===0;
    (cardinal?cardinalMarks:hourMarks).setMatrixAt(
      cardinal?cardinals++:hours++,markTransform.matrix);
  }
  hourMarks.instanceMatrix.needsUpdate=true;
  cardinalMarks.instanceMatrix.needsUpdate=true;
  mechanism.add(hourMarks,cardinalMarks);

  // Lathe-turned floor mounting: the sphere is no longer suspended in midair.
  // Its spindle rises behind the chess table; the two arms of the bronze
  // crescent cradle the equatorial ring without occluding the central globe.
  // All coordinates stay in root space, outside the gently moving armature.
  const mountZ=-2.08;
  mesh(new THREE.CylinderGeometry(.43,.49,.23,24),woodRim,0,-.20,mountZ);
  mesh(new THREE.CylinderGeometry(.34,.43,.07,24),tarnished,0,-.06,mountZ);
  mesh(new THREE.CylinderGeometry(.095,.14,1.38,16),brass,0,.67,mountZ);
  mesh(new THREE.CylinderGeometry(.18,.12,.14,20),tarnished,0,1.30,mountZ);
  const cradlePoints=[
    [-1.26,2.50],[-1.13,1.93],[-.72,1.48],[0,1.33],
    [.72,1.48],[1.13,1.93],[1.26,2.50],
  ].map(([x,y])=>new THREE.Vector3(x,y,mountZ));
  mesh(new THREE.TubeGeometry(
    new THREE.CatmullRomCurve3(cradlePoints,false,'centripetal'),
    60,.051,8,false),brass);
  const bearingGeometry=new THREE.CylinderGeometry(.12,.12,.13,12);
  const bearings=new THREE.InstancedMesh(bearingGeometry,tarnished,2);
  const bearingTransform=new THREE.Object3D();
  for(const [index,x] of [-1,1].entries()){
    bearingTransform.position.set(x*1.26,2.50,mountZ);
    bearingTransform.rotation.set(Math.PI/2,0,0);
    bearingTransform.updateMatrix();
    bearings.setMatrixAt(index,bearingTransform.matrix);
  }
  bearings.instanceMatrix.needsUpdate=true;
  root.add(bearings);
  container.dataset.armillaryMount='floor-yoke';
  container.dataset.armillaryHourStuds=String(hours+cardinals);
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
  // The cartographer's desk: three real bound folios, a squat turned
  // inkwell and a curved quill. Small props stay beside the chessboard.
  // Shared paper edges and gilt spine bands are GPU-instanced, never dozens
  // of individually drawn decorative strips.
  const leatherCovers=[
    new THREE.MeshStandardMaterial({color:0x654339,roughness:.88}),
    new THREE.MeshStandardMaterial({color:0x435468,roughness:.86}),
    new THREE.MeshStandardMaterial({color:0x847053,roughness:.89}),
  ];
  const bookCaseGeometry=new RoundedBoxGeometry(.94,.112,.64,2,.019);
  const paperEdges=new THREE.InstancedMesh(
    new THREE.BoxGeometry(.84,.062,.57),ivory,3);
  const bindingBands=new THREE.InstancedMesh(
    new THREE.BoxGeometry(.027,.075,.037),brass,6);
  const folioTransform=new THREE.Object3D();
  let spineBandCount=0;
  for(let i=0;i<3;i++){
    const centerY=1.085+i*.116;
    const centerZ=.05+i*.025;
    const volume=mesh(bookCaseGeometry,leatherCovers[i],-2.50,centerY,centerZ);
    volume.rotation.y=(i-1)*.045;
    // Exposed paper sits within the raised leather cover, not outside it.
    folioTransform.position.set(-2.426,centerY,centerZ+.018);
    folioTransform.rotation.set(0,0,0);
    folioTransform.updateMatrix();
    paperEdges.setMatrixAt(i,folioTransform.matrix);
    for(const z of [centerZ-.215,centerZ+.215]){
      folioTransform.position.set(-2.979,centerY,z);
      folioTransform.rotation.set(0,0,0);
      folioTransform.updateMatrix();
      bindingBands.setMatrixAt(spineBandCount++,folioTransform.matrix);
    }
  }
  paperEdges.instanceMatrix.needsUpdate=true;
  bindingBands.instanceMatrix.needsUpdate=true;
  root.add(paperEdges,bindingBands);
  const inkX=-2.65,inkZ=1.63;
  const inkProfile=[
    [0,0],[.135,0],[.175,.019],[.179,.045],[.166,.061],
    [.146,.071],[.127,.11],[.123,.17],[.135,.211],
    [.147,.239],[.142,.255],[.106,.260],[0,.260],
  ].map(([radius,height])=>new THREE.Vector2(radius,height));
  mesh(new THREE.LatheGeometry(inkProfile,22),obsidian,inkX,1.007,inkZ);
  torus(.137,.014,tarnished,inkX,1.252,inkZ,Math.PI/2);
  const ink=mesh(new THREE.CircleGeometry(.104,20),
    new THREE.MeshStandardMaterial({color:0x111b23,roughness:.26,metalness:.08}),
    inkX,1.266,inkZ);
  ink.rotation.x=-Math.PI/2;
  // Slim natural quill curves away from the ink, with a paired feather vane.
  const quillPath=new THREE.CatmullRomCurve3([
    new THREE.Vector3(-2.65,1.22,1.63),
    new THREE.Vector3(-2.61,1.51,1.63),
    new THREE.Vector3(-2.49,1.82,1.63),
    new THREE.Vector3(-2.40,2.05,1.63),
  ]);
  mesh(new THREE.TubeGeometry(quillPath,24,.011,6,false),oldVellum);
  const vane=new THREE.Shape();
  vane.moveTo(0,0);
  vane.bezierCurveTo(-.14,.13,-.13,.41,-.015,.54);
  vane.bezierCurveTo(.14,.42,.11,.20,0,0);
  const feather=mesh(new THREE.ShapeGeometry(vane,12),
    new THREE.MeshStandardMaterial({
      color:0xc5b59c,roughness:.96,side:THREE.DoubleSide,
    }),-2.49,1.55,1.64);
  feather.rotation.z=-.27;
  container.dataset.deskStillLife='folios-3-inkwell-quill';

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
