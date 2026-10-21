
import * as THREE from 'three';

/**
 * A standalone, easy-to-remove material and architecture study.
 * The final gallery must use authored/verified GLB + compressed textures.
 * Architectural details are batched where possible; avoid cast shadows here.
 */
function stoneTexture() {
  const size = 256;
  const canvas = document.createElement('canvas');
  canvas.width = canvas.height = size;
  const ctx = canvas.getContext('2d');
  const image = ctx.createImageData(size, size);
  let seed = 592112;
  const rng=() => {
    seed=(Math.imul(seed,1664525)+1013904223)>>>0;
    return seed/4294967296;
  };
  for(let y=0;y<size;y++){
    for(let x=0;x<size;x++){
      const band=8*Math.sin(y*.07)+4*Math.sin(x*.045+y*.1);
      const grain=(rng()-.5)*24 + band;
      const g=Math.max(0,Math.min(255,124+grain));
      const index=4*(y*size+x);
      image.data[index]=g;
      image.data[index+1]=g+2;
      image.data[index+2]=g+5;
      image.data[index+3]=255;
    }
  }
  ctx.putImageData(image,0,0);
  const texture=new THREE.CanvasTexture(canvas);
  texture.colorSpace=THREE.SRGBColorSpace;
  texture.wrapS=texture.wrapT=THREE.RepeatWrapping;
  texture.repeat.set(3,3);
  texture.anisotropy=4;
  return texture;
}

function archCurve(x,z,offset=0){
  const w=1.09+offset;
  const points=[
    [-w,.12],[-w,1.45],[-w*.92,2.22],
    [-w*.65,2.75],[-w*.31,3.14],[0,3.28+offset],
    [w*.31,3.14],[w*.65,2.75],[w*.92,2.22],
    [w,1.45],[w,.12],
  ].map(([px,py])=>new THREE.Vector3(x+px,py,z));
  return new THREE.CatmullRomCurve3(points,false,'centripetal');
}

export function addGalleryArchitecture(scene, coords, mobile=false){
  const sharedTexture=stoneTexture();
  const stone = new THREE.MeshStandardMaterial({
    color:0x4d5767,roughness:.86,metalness:.05,map:sharedTexture
  });
  const bronze = new THREE.MeshStandardMaterial({
    color:0xb4a17b, metalness:.77, roughness:.33
  });
  const wall=new THREE.Mesh(new THREE.PlaneGeometry(15,7),stone);
  wall.position.set(0,2.9,-1.65);
  scene.add(wall);
  const floor=new THREE.Mesh(new THREE.PlaneGeometry(20,19),stone);
  floor.rotation.x=-Math.PI/2;
  floor.position.y=-.60;
  scene.add(floor);

  // Fine perspective inlay instead of dozens of independent tile meshes.
  const inlay=new THREE.LineBasicMaterial({color:0xb79d75,transparent:true,opacity:.27});
  const lines=[];
  for(let x=-9;x<=9;x+=2.25)lines.push(x,-.588,-9,x,-.588,8);
  for(let z=-8;z<=8;z+=2.25)lines.push(-9,-.587,z,9,-.587,z);
  const wire=new THREE.BufferGeometry();
  wire.setAttribute('position',new THREE.Float32BufferAttribute(lines,3));
  const grout=new THREE.LineSegments(wire,inlay);
  scene.add(grout);

  // Stone vault ribs repeat via shared geometry, not primitive kitbash blocks.
  for(const x of coords){
    for(const [z,diameter,material] of [
      [-.94,.19,stone],[-.82,.085,bronze],[-.63,.07,stone]
    ]){
      const arch=new THREE.Mesh(
        new THREE.TubeGeometry(archCurve(x,z),100,diameter,10,false),
        material
      );
      scene.add(arch);
    }
    for(const side of [-1,1]){
      const pole=new THREE.Mesh(new THREE.CylinderGeometry(.19,.24,2.55,24),stone);
      pole.position.set(x+side*1.08,1.28,-.90);
      scene.add(pole);
      const collar=new THREE.Mesh(new THREE.CylinderGeometry(.27,.26,.12,24),bronze);
      collar.position.set(x+side*1.08,2.57,-.90);
      scene.add(collar);
    }
  }
  // A gallery lintel ties the separate worlds together as one observatory.
  const lintel = new THREE.Mesh(new THREE.BoxGeometry(11.75,.16,.32),bronze);
  lintel.position.set(0,3.67,-1.06);
  scene.add(lintel);
  const lintelStone = new THREE.Mesh(new THREE.BoxGeometry(12,.27,.53),stone);
  lintelStone.position.set(0,3.94,-1.05);
  scene.add(lintelStone);
  // Repeating gold inlays: instantiate for a bounded draw-call footprint.
  if(!mobile){
    const geo=new THREE.BoxGeometry(.055,.12,.015);
    const marks=new THREE.InstancedMesh(geo,bronze,88);
    const pose=new THREE.Object3D();
    for(let i=0;i<88;i++){
      pose.position.set(-5.75+i*(11.5/87),3.83,-.76);
      pose.updateMatrix();
      marks.setMatrixAt(i,pose.matrix);
    }
    marks.instanceMatrix.needsUpdate=true;
    scene.add(marks);
  }
  const galleryLight=new THREE.PointLight(0xdfc89f,7.5,14,2);
  galleryLight.position.set(0,4.7,2.2);
  scene.add(galleryLight);
  return { dispose:()=>sharedTexture.dispose() };
}
