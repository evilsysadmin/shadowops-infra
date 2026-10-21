import * as THREE from 'three';
import { mkdir, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

// Author-controlled geometry, PBR materials, no third-party model license.
// This small armillary is a GLB pipeline pilot, NOT finished premium scene art.
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const materials=[
 {name:'Brushed champagne brass',pbrMetallicRoughness:{baseColorFactor:[.62,.46,.26,1],metallicFactor:.86,roughnessFactor:.33},doubleSided:true},
 {name:'Patinated midnight bronze',pbrMetallicRoughness:{baseColorFactor:[.075,.113,.145,1],metallicFactor:.73,roughnessFactor:.48},doubleSided:true},
 {name:'Verdigris enamel',pbrMetallicRoughness:{baseColorFactor:[.075,.36,.37,1],metallicFactor:.33,roughnessFactor:.23},emissiveFactor:[.025,.11,.12],doubleSided:true}
];
const groups=materials.map(()=>({pos:[],norm:[],uv:[],indices:[]}));
function part(geo,mat=0,loc=[0,0,0],rot=[0,0,0]){
 const out=groups[mat],origin=out.pos.length/3;
 const matrix=new THREE.Matrix4().compose(new THREE.Vector3(...loc),
   new THREE.Quaternion().setFromEuler(new THREE.Euler(...rot)),new THREE.Vector3(1,1,1));
 const nmat=new THREE.Matrix3().getNormalMatrix(matrix);
 const positions=geo.getAttribute('position'),normals=geo.getAttribute('normal'),uvs=geo.getAttribute('uv');
 const p=new THREE.Vector3(),n=new THREE.Vector3();
 for(let i=0;i<positions.count;i++){
   p.fromBufferAttribute(positions,i).applyMatrix4(matrix);
   n.fromBufferAttribute(normals,i).applyMatrix3(nmat).normalize();
   out.pos.push(p.x,p.y,p.z);out.norm.push(n.x,n.y,n.z);out.uv.push(uvs.getX(i),uvs.getY(i));
 }
 if(geo.index)for(let i=0;i<geo.index.count;i++)out.indices.push(origin+geo.index.getX(i));
 else for(let i=0;i<positions.count;i++)out.indices.push(origin+i);
 geo.dispose();
}
const torus=(r,t,y,rot,mat=0)=>part(new THREE.TorusGeometry(r,t,8,72),mat,[0,y,0],rot);
const plinth=(a,b,height,y,mat)=>part(new THREE.CylinderGeometry(a,b,height,48),mat,[0,y,0]);
plinth(.58,.68,.16,0,1);plinth(.47,.52,.09,.14,0);plinth(.24,.34,.48,.41,1);
plinth(.30,.24,.085,.68,0);
torus(.48,.027,.22,[Math.PI/2,0,0]);
torus(.43,.016,.69,[Math.PI/2,0,0]);
const cy=1.45;
torus(.91,.032,cy,[Math.PI/2,.1,0]);
torus(.83,.021,cy,[0,0,Math.PI*.22]);
torus(.79,.025,cy,[Math.PI*.34,Math.PI*.29,Math.PI*.18]);
torus(.75,.018,cy,[Math.PI*.56,0,Math.PI*.4]);
torus(.68,.018,cy,[0,Math.PI*.2,Math.PI*.56]);
torus(.59,.013,cy,[Math.PI*.22,Math.PI*.33,Math.PI*.3],2);
part(new THREE.SphereGeometry(.22,24,16),2,[0,cy,0]);
part(new THREE.SphereGeometry(.089,16,12),0,[.64,cy+.13,.08]);
part(new THREE.SphereGeometry(.062,12,10),0,[-.41,cy-.47,.21]);
part(new THREE.SphereGeometry(.073,12,10),2,[.12,cy+.63,.14]);
for(let i=0;i<24;i++){
 const a=i*Math.PI/12;
 part(new THREE.BoxGeometry(i%6===0?.022:.012,.018,i%6===0?.086:.046),
  0,[Math.sin(a)*.49,.205,Math.cos(a)*.49],[0,a,0]);
}
part(new THREE.CylinderGeometry(.016,.016,1.89,16),0,[0,cy,0],[Math.PI*.10,0,Math.PI*.19]);

// Valid GLB 2.0 writer. Each PBR material is ONE merged indexed primitive,
// so placing two copies only adds six draw calls to the existing observatory.
const chunks=[],views=[],accessors=[];
function view(buffer,target){
 const offset=chunks.reduce((n,b)=>n+b.length,0),pad=(4-buffer.length%4)%4;
 chunks.push(buffer,Buffer.alloc(pad));
 return views.push({buffer:0,byteOffset:offset,byteLength:buffer.length,target})-1;
}
function attr(values,componentType,type,target,dim){
 const data=componentType===5125?Uint32Array.from(values):Float32Array.from(values);
 const buffer=Buffer.from(data.buffer,data.byteOffset,data.byteLength);
 const entry={bufferView:view(buffer,target),componentType,count:values.length/dim,type};
 if(type==='VEC3' && target===34962 && componentType===5126){
  entry.min=[Infinity,Infinity,Infinity];entry.max=[-Infinity,-Infinity,-Infinity];
  for(let i=0;i<values.length;i+=3)for(let j=0;j<3;j++){
   entry.min[j]=Math.min(entry.min[j],values[i+j]);
   entry.max[j]=Math.max(entry.max[j],values[i+j]);
  }
 }
 return accessors.push(entry)-1;
}
const primitives=groups.map((g,i)=>({
 attributes:{
  POSITION:attr(g.pos,5126,'VEC3',34962,3),
  NORMAL:attr(g.norm,5126,'VEC3',34962,3),
  TEXCOORD_0:attr(g.uv,5126,'VEC2',34962,2),
 },
 indices:attr(g.indices,5125,'SCALAR',34963,1),
 material:i,mode:4
}));
const bin=Buffer.concat(chunks);
const gltf={asset:{version:'2.0',generator:'ShadowOps armillary sculpture v1'},
 scene:0,scenes:[{nodes:[0]}],nodes:[{name:'ShadowOps armillary',mesh:0}],
 meshes:[{name:'Celestial instrument',primitives}],materials,
 buffers:[{byteLength:bin.length}],bufferViews:views,accessors};
const json=Buffer.from(JSON.stringify(gltf));
const jp=(4-json.length%4)%4,bp=(4-bin.length%4)%4;
const size=12+8+json.length+jp+8+bin.length+bp;
const result=Buffer.alloc(size);
result.writeUInt32LE(0x46546c67,0);result.writeUInt32LE(2,4);result.writeUInt32LE(size,8);
result.writeUInt32LE(json.length+jp,12);result.writeUInt32LE(0x4e4f534a,16);
json.copy(result,20);result.fill(0x20,20+json.length,20+json.length+jp);
const binaryOffset=20+json.length+jp;
result.writeUInt32LE(bin.length+bp,binaryOffset);result.writeUInt32LE(0x004e4942,binaryOffset+4);
bin.copy(result,binaryOffset+8);
const hash=createHash('sha256').update(result).digest('hex');
if(size>950000)throw Error('Armillary asset exceeds 950KB budget');
const name='armillary-'+hash.slice(0,12)+'.glb';
await mkdir(path.join(root,'public','art'),{recursive:true});
await writeFile(path.join(root,'public','art',name),result);
await writeFile(path.join(root,'src','armillaryAsset.generated.mjs'),
 "// Auto-generated by art/build-armillary.mjs; do not edit.\n"+
 "export const ARMILLARY_ASSET = '/art/"+name+"';\n"+
 "export const ARMILLARY_SHA256 = '"+hash+"';\n");
console.log('GLB '+name+' bytes '+size+' triangles '+groups.reduce((n,g)=>n+g.indices.length/3,0));
