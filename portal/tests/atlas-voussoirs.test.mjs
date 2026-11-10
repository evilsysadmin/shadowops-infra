import test from 'node:test';
import assert from 'node:assert/strict';
import * as THREE from 'three';
import {makeAtlasVoussoirGeometry} from '../experiments/atlas-chamber/atlasVoussoirs.mjs';

const left=()=>new THREE.CubicBezierCurve3(
  new THREE.Vector3(2.90,3.79,-4.79),
  new THREE.Vector3(3.02,4.39,-4.79),
  new THREE.Vector3(3.86,4.81,-4.79),
  new THREE.Vector3(4.175,4.95,-4.79),
);
const right=()=>new THREE.CubicBezierCurve3(
  new THREE.Vector3(4.175,4.95,-4.79),
  new THREE.Vector3(4.49,4.81,-4.79),
  new THREE.Vector3(5.33,4.39,-4.79),
  new THREE.Vector3(5.45,3.79,-4.79),
);

test('arch is fourteen separate tapered voussoirs, batched as a single solid geometry',()=>{
  const geo=makeAtlasVoussoirGeometry([left(),right()]);
  assert.equal(geo.userData.voussoirCount,14);
  assert.equal(geo.getAttribute('position').count,14*6*6);
  assert.equal(geo.getAttribute('position').count/3,168);
  assert.equal(geo.groups.length,0,'no hidden secondary draw/material groups');
  assert.equal(geo.index,null,'flat masonry faces should not share smoothed normals');
  const pos=geo.getAttribute('position'),uv=geo.getAttribute('uv'),normal=geo.getAttribute('normal');
  assert.equal(uv.count,pos.count);
  assert.equal(normal.count,pos.count);
  for(let i=0;i<pos.count;i++){
    for(const value of [pos.getX(i),pos.getY(i),pos.getZ(i),
      uv.getX(i),uv.getY(i),normal.getX(i),normal.getY(i),normal.getZ(i)])
      assert.ok(Number.isFinite(value),'finite 3D coordinate/UV/normal');
    const magnitude=Math.hypot(normal.getX(i),normal.getY(i),normal.getZ(i));
    assert.ok(Math.abs(magnitude-1)<1e-4,'real solid face has unit normal');
  }
  // Faces, not an open line/tube: front and back must have opposite normals.
  assert.ok(normal.getZ(0)>.99);
  assert.ok(normal.getZ(6)<-.99);
  assert.ok(geo.boundingBox.min.x>2.7 && geo.boundingBox.max.x<5.65,
    'do not enter the moonlit center window');
  assert.ok(geo.boundingBox.min.y>3.55 && geo.boundingBox.max.y<5.2);
  assert.ok(Math.abs(geo.boundingBox.min.z-(-5.01))<1e-4);
  assert.ok(Math.abs(geo.boundingBox.max.z-(-4.72))<1e-4);
  // Each 36-vertex stone ends BEFORE the next stone starts: visible joints.
  for(const start of [0,7*36]){
    for(let i=0;i<6;i++){
      const endVertex=start+i*36+1;
      const nextVertex=start+(i+1)*36;
      const gap=Math.hypot(pos.getX(endVertex)-pos.getX(nextVertex),
        pos.getY(endVertex)-pos.getY(nextVertex));
      assert.ok(gap>.007 && gap<.06,'separate but believable mortar joint');
    }
  }
  geo.dispose();
});

test('arch factory rejects missing or uninspectable curve pairs',()=>{
  for(const bad of [[],[left()],null,[left(),{}],[{},right()]]){
    assert.throws(()=>makeAtlasVoussoirGeometry(bad),TypeError);
  }
});
