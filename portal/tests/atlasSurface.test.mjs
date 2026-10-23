import {test} from 'node:test';
import assert from 'node:assert/strict';
import {makeAtlasSurfaceTexels,makeAtlasNormalTexels} from '../experiments/atlas-chamber/atlasSurface.mjs';

test('Atlas Chamber wood and stone patina are deterministic, bounded and textured',()=>{
  for(const kind of ['wood','stone']){
    const a=makeAtlasSurfaceTexels(kind,128);
    const b=makeAtlasSurfaceTexels(kind,128);
    assert.deepEqual(a.data,b.data);
    assert.equal(a.data.length,128*128*4);
    const sample=new Set();
    for(let i=0;i<a.data.length;i+=128)sample.add(a.data[i]);
    assert.ok(sample.size>12,kind+' surface must have nontrivial visual variation');
    for(let i=3;i<a.data.length;i+=4)assert.equal(a.data[i],255);
  }
});

test('Atlas Chamber patina denies unreasonable texture sizes and arbitrary modes',()=>{
  assert.throws(()=>makeAtlasSurfaceTexels('wood',1024),RangeError);
  assert.throws(()=>makeAtlasSurfaceTexels('lava',256),RangeError);
  assert.throws(()=>makeAtlasSurfaceTexels('stone',32),RangeError);
});

test('Atlas surface relief uses bounded, deterministic tangent-space normals',()=>{
  for(const kind of ['wood','stone']){
    const first=makeAtlasNormalTexels(kind,128);
    const second=makeAtlasNormalTexels(kind,128);
    assert.deepEqual(first.data,second.data);
    assert.equal(first.data.length,128*128*4);
    const tangent=new Set();
    let zMin=255,zMax=0;
    for(let i=0;i<first.data.length;i+=4){
      const [r,g,b,a]=first.data.subarray(i,i+4);
      assert.equal(a,255);
      assert.ok(b>=205,'no inverted or near-horizontal normals');
      tangent.add(r+':'+g);
      zMin=Math.min(zMin,b);zMax=Math.max(zMax,b);
    }
    assert.ok(tangent.size>30,kind+' needs real directional surface variation');
    assert.ok(zMax>zMin,kind+' normal blue component cannot be flat');
    assert.ok(first.data.byteLength<=128*128*4,'strict RGBA8 texture budget');
  }
  assert.throws(()=>makeAtlasNormalTexels('lava'),RangeError);
  assert.throws(()=>makeAtlasNormalTexels('stone',1024),RangeError);
});
