import {test} from 'node:test';
import assert from 'node:assert/strict';
import {makeAtlasSurfaceTexels} from '../experiments/atlas-chamber/atlasSurface.mjs';

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
