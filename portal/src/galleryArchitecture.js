import * as THREE from 'three';

// Deterministic, locally created materials: no opaque external assets,
// no blocking texture fetches, and no random output between CI screenshots.
// These maps are an architectural study, not a replacement for final GLB art.
function materialMaps() {
  const size = 256;
  const heights = new Float32Array(size * size);
  const pixels = new Uint8Array(size * size * 4);
  const normals = new Uint8Array(size * size * 4);
  const roughness = new Uint8Array(size * size * 4);
  const hash = (x, y) => {
    let n = Math.imul(x | 0, 374761393) + Math.imul(y | 0, 668265263);
    n = Math.imul(n ^ (n >>> 13), 1274126177);
    return ((n ^ (n >>> 16)) >>> 0) / 4294967295;
  };
  // Relief across the edges tiles with the baseColor/normal textures.
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const jointY = Math.min(y % 64, 64 - y % 64);
      const shiftedX = (x + (Math.floor(y / 64) % 2 ? 64 : 0)) % 128;
      const jointX = Math.min(shiftedX, 128 - shiftedX);
      const seam = jointY < 2 || jointX < 2 ? -.22 : 0;
      const low = .07 * Math.sin(x * .086) * Math.sin(y * .073);
      const mid = .032 * Math.sin(x * .32 + y * .17);
      const grit = (hash(x,y) - .5) * .072;
      heights[y * size + x] = .55 + low + mid + grit + seam;
    }
  }
  for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) {
    const at = (a,b) => heights[((b + size) % size) * size + ((a + size) % size)];
    const i = (y * size + x) * 4;
    const h = at(x,y);
    const speck = (hash(x+71,y+23) - .5) * 13;
    const value = Math.max(22, Math.min(226, 164 + (h - .55) * 108 + speck));
    pixels[i] = value;
    pixels[i+1] = value + 1;
    pixels[i+2] = value + 4;
    pixels[i+3] = 255;
    const dx = (at(x+1,y) - at(x-1,y)) * 1.85;
    const dy = (at(x,y+1) - at(x,y-1)) * 1.85;
    const nx = -dx, ny = -dy, nz = 1;
    const len = Math.hypot(nx,ny,nz);
    normals[i] = Math.round((nx/len*.5+.5)*255);
    normals[i+1] = Math.round((ny/len*.5+.5)*255);
    normals[i+2] = Math.round((nz/len*.5+.5)*255);
    normals[i+3] = 255;
    // Three.js reads GREEN for roughness.
    roughness[i] = roughness[i+2] = 228;
    roughness[i+1] = Math.max(165, Math.min(250, Math.round(216 + (hash(x+41,y+51)-.5)*32)));
    roughness[i+3] = 255;
  }
  function tex(data, isColor=false) {
    const result = new THREE.DataTexture(data,size,size,THREE.RGBAFormat,THREE.UnsignedByteType);
    result.wrapS = result.wrapT = THREE.RepeatWrapping;
    result.minFilter = THREE.LinearMipmapLinearFilter;
    result.magFilter = THREE.LinearFilter;
    result.generateMipmaps = true;
    result.anisotropy = 4;
    if (isColor) result.colorSpace = THREE.SRGBColorSpace;
    result.needsUpdate = true;
    return result;
  }
  const textures = [tex(pixels,true),tex(normals),tex(roughness)];
  return {textures, color:textures[0], normal:textures[1], rough:textures[2]};
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
  const back = new THREE.Mesh(new THREE.PlaneGeometry(15,7),stone);
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
    dispose() { for(const texture of maps.textures) texture.dispose(); },
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
