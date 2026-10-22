import * as THREE from 'three';
import { GlbSculpture, writeManifest } from './glbWriter.mjs';

const materials=[
 {name:'Brushed champagne brass',pbrMetallicRoughness:{baseColorFactor:[.62,.46,.26,1],metallicFactor:.86,roughnessFactor:.33},doubleSided:true},
 {name:'Patinated midnight bronze',pbrMetallicRoughness:{baseColorFactor:[.075,.113,.145,1],metallicFactor:.73,roughnessFactor:.48},doubleSided:true},
 {name:'Verdigris enamel',pbrMetallicRoughness:{baseColorFactor:[.075,.36,.37,1],metallicFactor:.33,roughnessFactor:.23},emissiveFactor:[.025,.11,.12],doubleSided:true}
];
const sculpture=new GlbSculpture(materials);
const part=(...args)=>sculpture.part(...args);
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

const armillary=await sculpture.write('armillary');
await writeManifest('armillaryAsset.generated.mjs',{
 ARMILLARY_ASSET:armillary.url,
 ARMILLARY_SHA256:armillary.sha256,
});
