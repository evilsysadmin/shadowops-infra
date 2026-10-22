import * as THREE from 'three';

// Deterministic, locally created materials: no opaque external assets,
// no blocking texture fetches, and no random output between CI screenshots.
// These maps are an architectural study, not a replacement for final GLB art.
// Original seamless slate material authored deterministically from multiscale
// mineral strata. Bounded textures, no network, runtime shaders or DCC assets.
// The three existing GPU textures are reused: albedo, normal and roughness.
export function buildStratifiedStoneTexels(size = 256) {
  if (!Number.isInteger(size) || size < 64 || size > 512 || size % 64 !== 0)
    throw new RangeError('Stone texture must be a 64px-aligned square between 64 and 512');
  const heights = new Float32Array(size * size);
  const pixels = new Uint8Array(size * size * 4);
  const normals = new Uint8Array(size * size * 4);
  const roughness = new Uint8Array(size * size * 4);
  const hash = (x,y) => {
    let n = Math.imul(x | 0, 374761393) + Math.imul(y | 0, 668265263);
    n = Math.imul(n ^ (n >>> 13), 1274126177);
    return ((n ^ (n >>> 16)) >>> 0) / 4294967295;
  };
  const smooth = t => t * t * (3 - 2 * t);
  // Periodic interpolation: the entire material tiles with no hard edge.
  function strata(x,y,frequency) {
    const u=x*frequency/size, v=y*frequency/size;
    const xi=Math.floor(u), yi=Math.floor(v), fx=smooth(u-xi),fy=smooth(v-yi);
    const a=hash(xi%frequency,yi%frequency);
    const b=hash((xi+1)%frequency,yi%frequency);
    const c=hash(xi%frequency,(yi+1)%frequency);
    const d=hash((xi+1)%frequency,(yi+1)%frequency);
    return (a+(b-a)*fx)*(1-fy)+(c+(d-c)*fx)*fy;
  }
  const clamp=v=>Math.max(0,Math.min(255,Math.round(v)));
  for(let y=0;y<size;y++)for(let x=0;x<size;x++){
    const fx=x*256/size, fy=y*256/size;
    const large=strata(x,y,4)-.5;
    const medium=strata(x,y,12)-.5;
    const small=strata(x,y,32)-.5;
    const grit=hash(x,y)-.5;
    // Tiny horizontal bedding and warped joints; no chessboard-like grid.
    const warp=large*5+medium*2.2;
    const row=Math.floor((fy+warp+256)%256/64);
    const jointY=Math.min((fy+warp+256)%64,64-(fy+warp+256)%64);
    const stagger= row%2===0 ? 0 : 51;
    const jointX=Math.min((fx+stagger+medium*5+512)%128,128-(fx+stagger+medium*5+512)%128);
    const mortar=jointY<1.15||jointX<1.0 ? 1 : 0;
    const band=Math.sin((fy+warp*3)*.091+large*3)*.038;
    const mineral=large*.54+medium*.31+small*.15;
    const vein=Math.max(0,small+.1)*.045;
    const h=.55+mineral*.24+band+vein+grit*.035-mortar*.12;
    heights[y*size+x]=h;
    // Nearly neutral mineral grey; subtle iron/copper pockets warm the slate
    // while blue mica picks up cold moonlight, not sprayed-on portal colors.
    const oxide=Math.max(0,medium+.11);
    const base=170+mineral*38+band*58+grit*13-mortar*16;
    const i=(y*size+x)*4;
    pixels[i]=clamp(base+oxide*17-3);
    pixels[i+1]=clamp(base+2-oxide*4);
    pixels[i+2]=clamp(base+7-oxide*11);
    pixels[i+3]=255;
    // Physically inspired roughness variation: mortar matte, polished
    // mineral grains slightly smoother. GREEN channel is Three.js roughness.
    const rough=218+grit*22-mineral*26+mortar*20;
    roughness[i]=roughness[i+2]=228;
    roughness[i+1]=clamp(rough);
    roughness[i+3]=255;
  }
  const heightAt=(x,y)=>heights[((y+size)%size)*size+(x+size)%size];
  for(let y=0;y<size;y++)for(let x=0;x<size;x++){
    const i=(y*size+x)*4;
    const dx=(heightAt(x+1,y)-heightAt(x-1,y))*1.45;
    const dy=(heightAt(x,y+1)-heightAt(x,y-1))*1.45;
    const length=Math.hypot(dx,dy,1);
    normals[i]=clamp((-.0-dx)/length*127.5+127.5);
    normals[i+1]=clamp(-dy/length*127.5+127.5);
    normals[i+2]=clamp(1/length*127.5+127.5);
    normals[i+3]=255;
  }
  return {size,pixels,normals,roughness};
}
function materialMaps() {
  const {size,pixels,normals,roughness}=buildStratifiedStoneTexels();
  function tex(data,isColor=false) {
    const t=new THREE.DataTexture(data,size,size,THREE.RGBAFormat,THREE.UnsignedByteType);
    t.wrapS=t.wrapT=THREE.RepeatWrapping;
    t.minFilter=THREE.LinearMipmapLinearFilter;
    t.magFilter=THREE.LinearFilter;
    t.generateMipmaps=true;
    t.anisotropy=4;
    if(isColor)t.colorSpace=THREE.SRGBColorSpace;
    t.needsUpdate=true;
    return t;
  }
  const textures=[tex(pixels,true),tex(normals),tex(roughness)];
  return {textures,color:textures[0],normal:textures[1],rough:textures[2]};
}
function archCurve(x,z) {
  const w=1.085;
  return new THREE.CatmullRomCurve3([
    [-w,.14],[-w,1.43],[-w*.93,2.22],[-w*.65,2.76],
    [-w*.31,3.12],[0,3.27],[w*.31,3.12],
    [w*.65,2.76],[w*.93,2.22],[w,1.43],[w,.14],
  ].map(([px,py])=>new THREE.Vector3(x+px,py,z)),false,'centripetal');
}
export function addGalleryArchitecture(scene, coords, mobile=false) {
  const maps=materialMaps();
  const stone = new THREE.MeshStandardMaterial({
    color:0x4d5563, metalness:.035, roughness:1,
    map:maps.color, normalMap:maps.normal, roughnessMap:maps.rough,
    normalScale:new THREE.Vector2(.42,.42),
  });
  const bronze = new THREE.MeshStandardMaterial({
    color:0xb6a17d,metalness:.73,roughness:.31,
  });
  const dark = new THREE.MeshStandardMaterial({
    color:0x121923,metalness:.20,roughness:.69,
  });
  // Low-intensity color bleeding is baked into one 128 KiB RGBA map.
  // Only the shared wall receives it: the floor, portal panes and stone
  // fallback keep their previous materials and navigation semantics.
  const lightmap = createStoneGrazingLightmap();
  const wallStone = stone.clone();
  wallStone.emissive = new THREE.Color(0xffffff);
  wallStone.emissiveMap = lightmap;
  wallStone.emissiveIntensity = .44;
  const back = new THREE.Mesh(new THREE.PlaneGeometry(15,7),wallStone);
  back.position.set(0,2.9,-1.85);
  scene.add(back);
  const floor = new THREE.Mesh(new THREE.PlaneGeometry(20,19),stone);
  floor.rotation.x=-Math.PI/2;
  floor.position.y=-.59;
  scene.add(floor);
  // Arch-shaped dark alcoves: no rectangular panels peeking over the arch.
  const recessShape = new THREE.Shape();
  recessShape.moveTo(-1.025,0);
  recessShape.lineTo(1.025,0);
  recessShape.lineTo(1.025,1.47);
  recessShape.bezierCurveTo(1.025,2.58,.64,3.18,0,3.24);
  recessShape.bezierCurveTo(-.64,3.18,-1.025,2.58,-1.025,1.47);
  recessShape.closePath();
  const recessGeo = new THREE.ShapeGeometry(recessShape,32);
  const recesses = new THREE.InstancedMesh(recessGeo,dark,coords.length);
  const object = new THREE.Object3D();
  coords.forEach((x,i)=>{
    object.position.set(x,.12,-1.52);
    object.rotation.set(0,0,0);
    object.scale.set(1,1,1);
    object.updateMatrix();
    recesses.setMatrixAt(i,object.matrix);
  });
  recesses.instanceMatrix.needsUpdate=true;
  scene.add(recesses);

  // Floor inlay follows perspective rather than a floating platform grid.
  const inlay=new THREE.LineBasicMaterial({color:0xb9a27e,transparent:true,opacity:.26});
  const lines=[];
  for(let x=-9;x<=9;x+=2.25)lines.push(x,-.577,-9,x,-.577,8);
  for(let z=-8;z<=8;z+=2.25)lines.push(-9,-.576,z,9,-.576,z);
  const grid=new THREE.BufferGeometry();
  grid.setAttribute('position',new THREE.Float32BufferAttribute(lines,3));
  scene.add(new THREE.LineSegments(grid,inlay));

  // Sculpt a soft pool of light beneath each arch. Additive quads and a
  // compact shader share one material, not shadow maps or postprocessing.
  const GLOW_VERTEX = [
    'varying vec2 vUv;',
    'void main() { vUv = uv; gl_Position=projectionMatrix*modelViewMatrix*vec4(position,1.); }',
  ].join('\n');
  const GLOW_FRAGMENT = [
    'uniform vec3 uColor; varying vec2 vUv;',
    'void main(){',
    ' vec2 p=(vUv-.5)*vec2(1.5,1.);',
    ' float a=pow(max(0.,1.-length(p)*1.8),2.7)*.23;',
    ' gl_FragColor=vec4(uColor*a,a);',
    '}',
  ].join('\n');
  const groundLights=[];
  const palette=[0xc59b62,0xc9704a,0x54a5d4];
  coords.forEach((x,i)=>{
    const beamMat=new THREE.ShaderMaterial({
      vertexShader:GLOW_VERTEX, fragmentShader:GLOW_FRAGMENT,
      uniforms:{uColor:{value:new THREE.Color(palette[i])}},
      depthWrite:false,transparent:true,blending:THREE.AdditiveBlending,
      side:THREE.DoubleSide,
    });
    const beam = new THREE.Mesh(new THREE.PlaneGeometry(2.55,3.0),beamMat);
    beam.position.set(x,2.34,-1.42);
    scene.add(beam);
    groundLights.push(beam);
  });
  const topLight=new THREE.PointLight(0xdfb889,8,12,2);
  topLight.position.set(0,5,1.9);
  scene.add(topLight);
  const blueFill=new THREE.DirectionalLight(0x7c9ec4,.55);
  blueFill.position.set(4,3,5);
  scene.add(blueFill);
  let fallbackBuilt = false;
  return {
    activateFallback() {
      if (fallbackBuilt) return;
      fallbackBuilt = true;
      addFallbackMasonry(scene, coords, mobile, stone, bronze);
    },
    dispose() { for(const texture of maps.textures) texture.dispose(); lightmap.dispose(); },
  };
}

// Only run procedural mesh creation when the optional GLB is unavailable.
function addFallbackMasonry(scene, coords, mobile, stone, bronze) {
  const object=new THREE.Object3D();
  // Hand-cut voussoir impression from one shared instanced mesh, rather
  // than one GPU draw call per decorative stone. No low-poly block walls.
  const voussoirCount = mobile ? 39 : 63;
  // Bevelled stone key pieces catch highlights softly, without cuboid steps.
  const voussoirShape = new THREE.Shape();
  voussoirShape.moveTo(-.108,-.072);
  voussoirShape.lineTo(.108,-.072);
  voussoirShape.lineTo(.108,.072);
  voussoirShape.lineTo(-.108,.072);
  voussoirShape.closePath();
  const voussoirGeo = new THREE.ExtrudeGeometry(voussoirShape,{
    depth:.18, bevelEnabled:true, bevelThickness:.022, bevelSize:.022,
    bevelSegments:3, steps:1, curveSegments:4
  });
  const voussoirMat = stone.clone();
  voussoirMat.color.setHex(0x353d4c);
  const voussoirs = new THREE.InstancedMesh(voussoirGeo,voussoirMat,voussoirCount);
  let k=0;
  const up=new THREE.Vector3(0,1,0);
  for (const x of coords) {
    const curve=archCurve(x,-1.18);
    const n=mobile?13:21;
    for(let i=0;i<n;i++){
      const u=(i+.5)/n;
      const tangent=curve.getTangent(u).normalize();
      object.position.copy(curve.getPoint(u));
      object.quaternion.setFromUnitVectors(up,tangent);
      object.scale.set(1,1,1);
      object.updateMatrix();
      voussoirs.setMatrixAt(k++,object.matrix);
    }
  }
  voussoirs.instanceMatrix.needsUpdate = true;
  scene.add(voussoirs);

  // Bronze structural crowns make the three archways read as ONE hall.
  const upperBeam = new THREE.Mesh(new THREE.BoxGeometry(11.5,.11,.25),bronze);
  upperBeam.position.set(0,3.77,-1.18);
  scene.add(upperBeam);
  const stoneBeam = new THREE.Mesh(new THREE.BoxGeometry(12,.25,.45),stone);
  stoneBeam.position.set(0,4.04,-1.31);
  scene.add(stoneBeam);
  // Fluted, restrained shafts in place of the former rectangular pillars.
  const columnXs=[-4.45,-1.60,1.60,4.45];
  const pilasters=new THREE.InstancedMesh(new THREE.CylinderGeometry(.115,.155,2.76,40),stone,columnXs.length);
  const capitals=new THREE.InstancedMesh(new THREE.CylinderGeometry(.20,.20,.11,40),bronze,columnXs.length);
  columnXs.forEach((x,i)=>{
    object.position.set(x,1.45,-1.40);
    object.rotation.set(0,0,0);
    object.scale.set(1,1,1);
    object.updateMatrix();
    pilasters.setMatrixAt(i,object.matrix);
    object.position.set(x,2.90,-1.40);
    object.updateMatrix();
    capitals.setMatrixAt(i,object.matrix);
  });
  pilasters.instanceMatrix.needsUpdate = true;
  capitals.instanceMatrix.needsUpdate = true;
  scene.add(pilasters,capitals);

  return true;
}
