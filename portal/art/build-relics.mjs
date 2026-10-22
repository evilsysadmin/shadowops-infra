import * as THREE from 'three';
import { GlbSculpture, writeManifest } from './glbWriter.mjs';

// Three distinct source-authored relief sculptures, mounted in the gallery,
// outside the interactive panes. This is a small GLB artistic study, not final
// environment art; every face is original and there are no outside licenses.
const metals=[
 {name:'Mellow brass rim',pbrMetallicRoughness:{baseColorFactor:[.55,.40,.225,1],metallicFactor:.89,roughnessFactor:.32},doubleSided:true},
 {name:'Engraved graphite',pbrMetallicRoughness:{baseColorFactor:[.065,.08,.105,1],metallicFactor:.52,roughnessFactor:.50},doubleSided:true},
 {name:'Warm enamel',pbrMetallicRoughness:{baseColorFactor:[.42,.24,.09,1],metallicFactor:.30,roughnessFactor:.28},emissiveFactor:[.11,.055,.015],doubleSided:true},
];
const palettes={
 chess: metals,
 chronicles:[
  metals[0],metals[1],
  {name:'Distant ember',pbrMetallicRoughness:{baseColorFactor:[.7,.22,.055,1],metallicFactor:.10,roughnessFactor:.30},emissiveFactor:[.65,.11,.014],doubleSided:true},
 ],
 star:[
  {name:'Pewter alloy',pbrMetallicRoughness:{baseColorFactor:[.31,.50,.63,1],metallicFactor:.78,roughnessFactor:.29},doubleSided:true},
  metals[1],
  {name:'Cerulean enamel',pbrMetallicRoughness:{baseColorFactor:[.06,.29,.43,1],metallicFactor:.39,roughnessFactor:.24},emissiveFactor:[.025,.15,.25],doubleSided:true},
 ],
};
const REFERENCE=[['chess','A knight effigy'],['chronicles','A warden lantern'],['star','A star navigator']];
const outputs={};
for(const [id,title] of REFERENCE) {
 const s=new GlbSculpture(palettes[id]);
 const p=(...args)=>s.part(...args);
 const front=(geometry,material=0,x=0,y=0,z=.09,rotate=[0,0,0])=>p(geometry,material,[x,y,z],rotate);
 const disk=(r,thick,mat=1,z=0)=>front(new THREE.CylinderGeometry(r,r,thick,64),mat,0,0,z,[Math.PI/2,0,0]);
 // Round, engraved mounting: common design system across the three worlds.
 disk(.58,.11,1,-.07);disk(.52,.027,0,.017);
 front(new THREE.TorusGeometry(.49,.016,8,80),0,0,0,.065);
 front(new THREE.TorusGeometry(.425,.009,6,80),2,0,0,.078);
 if(id==='chess') {
   // Side-profile sculptural knight with a shaped snout and ears, not a glyph.
   const shape=new THREE.Shape();
   shape.moveTo(-.24,-.33);
   shape.lineTo(.24,-.33);
   shape.lineTo(.19,-.24);
   shape.lineTo(.08,-.17);
   shape.lineTo(.16,-.075);
   shape.quadraticCurveTo(.25,.06,.31,.19);
   shape.lineTo(.17,.23);
   shape.lineTo(.13,.36);
   shape.lineTo(.015,.27);
   shape.lineTo(-.06,.36);
   shape.lineTo(-.17,.25);
   shape.quadraticCurveTo(-.25,.16,-.18,.06);
   shape.lineTo(-.28,-.045);
   shape.lineTo(-.15,-.14);
   shape.lineTo(-.20,-.24);
   shape.closePath();
   front(new THREE.ExtrudeGeometry(shape,{depth:.095,bevelEnabled:true,bevelSegments:4,steps:1,bevelSize:.023,bevelThickness:.024}),0,0,0,.095);
   front(new THREE.SphereGeometry(.022,12,9),2,-.07,.19,.247);
   front(new THREE.BoxGeometry(.39,.055,.035),2,0,-.31,.17);
   front(new THREE.TorusGeometry(.16,.012,7,48,Math.PI),2,-.015,-.15,.238,[0,0,0]);
 } else if(id==='chronicles') {
   // Tall gothic lantern cage with layered roof, metal lattice and ember.
   const roof=new THREE.ConeGeometry(.29,.19,6);
   front(roof,0,0,.32,.16,[0,0,Math.PI/6]);
   front(new THREE.CylinderGeometry(.21,.27,.072,6),0,0,-.30,.20,[Math.PI/2,0,0]);
   front(new THREE.CylinderGeometry(.024,.024,.57,12),0,-.20,.0,.20);
   front(new THREE.CylinderGeometry(.024,.024,.57,12),0,.20,.0,.20);
   front(new THREE.CylinderGeometry(.024,.024,.50,12),0,0,.01,.15);
   front(new THREE.IcosahedronGeometry(.115,2),2,0,-.03,.205);
   front(new THREE.SphereGeometry(.045,16,12),2,0,.17,.222);
   front(new THREE.TorusGeometry(.095,.016,8,32),0,0,.39,.12);
 } else {
   // Astrogation device: tilted orrery and a small blue planetary core.
   front(new THREE.SphereGeometry(.165,32,18),2,0,.0,.16);
   front(new THREE.TorusGeometry(.32,.026,9,84),0,0,0,.18,[.31,.35,.25]);
   front(new THREE.TorusGeometry(.265,.018,9,84),0,0,0,.22,[-.38,.16,-.48]);
   front(new THREE.TorusGeometry(.215,.012,8,72),0,0,0,.15,[.64,.18,.40]);
   front(new THREE.SphereGeometry(.035,12,8),0,-.28,.13,.18);
   front(new THREE.SphereGeometry(.04,12,8),0,.28,-.18,.18);
   front(new THREE.SphereGeometry(.027,12,8),2,.02,.33,.15);
 }
 const entry=await s.write('relic-'+id,425000);
 outputs[id]={...entry,title,license:'Original ShadowOps authored relief'};
}
await writeManifest('worldRelics.generated.mjs',{WORLD_RELICS:outputs});
