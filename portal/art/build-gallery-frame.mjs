import * as THREE from 'three';
import {makeFlutedPilasterGeometry} from './flutedPillar.mjs';
import { GlbSculpture, writeManifest } from './glbWriter.mjs';

// Original authored portal gallery facade, exported once at build time.
// Geometry/materials are independent from UI/lighting/raycast. No Blender
// runtime, CDN request, external models or binary checked into Git.
const pbr=[
  {name:'Midnight honed stone',pbrMetallicRoughness:{baseColorFactor:[.038,.049,.068,1],metallicFactor:.035,roughnessFactor:.86},doubleSided:true},
  {name:'Aged satin brass',pbrMetallicRoughness:{baseColorFactor:[.29,.205,.11,1],metallicFactor:.76,roughnessFactor:.36},doubleSided:true},
  {name:'Carved slate shadow',pbrMetallicRoughness:{baseColorFactor:[.013,.019,.029,1],metallicFactor:.035,roughnessFactor:.94},doubleSided:true},
];
const model=new GlbSculpture(pbr);
const part=(geo,mat=0,pos=[0,0,0],rot=[0,0,0])=>model.part(geo,mat,pos,rot);
function curve(x,z) {
 const w=1.085;
 return new THREE.CatmullRomCurve3([
   [-w,.14],[-w,1.43],[-w*.93,2.22],[-w*.65,2.76],
   [-w*.31,3.12],[0,3.27],[w*.31,3.12],
   [w*.65,2.76],[w*.93,2.22],[w,1.43],[w,.14],
 ].map(([px,py])=>new THREE.Vector3(x+px,py,z)),false,'centripetal');
}
const xs=[-3.22,0,3.22];
// The two stepped courses stand BEHIND the existing playable glass, not in
// front of it. Each wider stone reveal catches grazing light at a different
// depth; no new mesh/material/draw is created after the GLB is merged.
function revealCurve(x,z,spread,rise) {
  const points=curve(x,z).getPoints(64).map(p=>new THREE.Vector3(
    x+(p.x-x)*spread,
    p.y+rise*(p.y-.14)/3.13,
    z,
  ));
  return new THREE.CatmullRomCurve3(points,false,'centripetal');
}
// Channeled structural arches, hand-sculpted voussoirs and nested bronze
// mouldings share three PBR meshes in the final GLB.
const up=new THREE.Vector3(0,1,0);
const keyShape=new THREE.Shape();
keyShape.moveTo(-.115,-.085);
keyShape.lineTo(.115,-.085);
keyShape.lineTo(.115,.085);
keyShape.lineTo(-.115,.085);
keyShape.closePath();
for(const x of xs) {
 // Double setback yields a real, shadowed stone archivolt instead of
 // stacking more glowing lines around the already illuminated portals.
 part(new THREE.TubeGeometry(revealCurve(x,-1.485,1.19,.13),96,.135,8,false),2);
 part(new THREE.TubeGeometry(revealCurve(x,-1.365,1.14,.085),96,.10,8,false),0);
 const border=curve(x,-1.18);
 part(new THREE.TubeGeometry(border,110,.107,10,false),0);
 part(new THREE.TubeGeometry(curve(x,-1.105),110,.022,7,false),1);
 part(new THREE.TubeGeometry(curve(x,-1.28),110,.087,9,false),2);
 const count=19;
 for(let i=0;i<count;i++) {
   const u=(i+.5)/count,point=border.getPoint(u);
   const tangent=border.getTangent(u).normalize();
   const turn=new THREE.Quaternion().setFromUnitVectors(up,tangent);
   const euler=new THREE.Euler().setFromQuaternion(turn);
   part(new THREE.ExtrudeGeometry(keyShape,{
      depth:.115,bevelEnabled:true,bevelThickness:.018,bevelSize:.015,
      bevelSegments:2,steps:1,curveSegments:2,
   }),0,[point.x,point.y,point.z+.035],[euler.x,euler.y,euler.z]);
 }
 // Diegetic keystone under the relief emblem, behind the clickable pane.
 part(new THREE.CylinderGeometry(.09,.12,.15,24),1,[x,3.29,-1.04],[Math.PI/2,0,0]);
}
// Four stone shafts now have genuine twelve-flute relief instead of
// unarticulated cylinders. Hand-set brass collars frame their chiseled edges.
// They join the same three existing PBR primitives: no extra runtime draws.
for(const x of [-4.45,-1.60,1.60,4.45]) {
 part(makeFlutedPilasterGeometry(),0,[x,1.45,-1.40]);
 for(const y of [.19,2.62]) {
   part(new THREE.TorusGeometry(y<1?.155:.126,.009,6,48),1,
     [x,y,-1.40],[Math.PI/2,0,0]);
 }
 part(new THREE.CylinderGeometry(.195,.195,.10,32),1,[x,2.89,-1.40]);
 part(new THREE.CylinderGeometry(.205,.205,.085,32),2,[x,.035,-1.40]);
 part(new THREE.CylinderGeometry(.13,.15,.105,32),1,[x,2.78,-1.40]);
}
// Continuous cornice above all three worlds; subtle lattice engraved in.
part(new THREE.BoxGeometry(12,.15,.40),0,[0,3.98,-1.31]);
part(new THREE.BoxGeometry(11.5,.09,.25),1,[0,3.78,-1.18]);
part(new THREE.BoxGeometry(11.7,.028,.24),2,[0,4.08,-1.19]);
for(let i=0;i<48;i++) {
 const x=-5.64+i*(11.28/47);
 part(new THREE.BoxGeometry(i%6===0?.031:.016,.055,.019),1,[x,3.877,-1.075]);
}
const entry=await model.write('gallery-frame',1650000);
if(entry.triangles>62000)throw Error('Gallery facade triangle budget exceeded');
await writeManifest('galleryFrame.generated.mjs',{
 GALLERY_FRAME_ASSET:entry.url,GALLERY_FRAME_SHA256:entry.sha256,
 GALLERY_FRAME_TRIANGLES:entry.triangles,GALLERY_FRAME_BYTES:entry.bytes,
});
