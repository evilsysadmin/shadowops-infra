import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {buildStratifiedStoneTexels} from '../src/galleryArchitecture.js';
test('stratified slate is deterministic, bounded and preserves existing texture cost',()=>{
  const a=buildStratifiedStoneTexels();
  const b=buildStratifiedStoneTexels();
  assert.equal(a.size,256);
  for(const name of ['pixels','normals','roughness']){
    assert.equal(a[name].byteLength,256*256*4);
    assert.equal(createHash('sha256').update(a[name]).digest('hex'),
      createHash('sha256').update(b[name]).digest('hex'));
  }
  const colors=[];
  const variation=[];
  for(let i=0;i<a.pixels.length;i+=4){
    assert.equal(a.pixels[i+3],255);
    assert.equal(a.normals[i+3],255);
    assert.equal(a.roughness[i+3],255);
    const rr=a.roughness[i+1];
    assert.ok(rr>=175&&rr<=250,'slate roughness stays conservative');
    colors.push(a.pixels[i]);
    variation.push(a.normals[i+2]);
  }
  const min=Math.min(...new Set(colors)),max=Math.max(...new Set(colors));
  assert.ok(min>105&&max<225,'no overly black or luminous painted slate');
  assert.ok(max-min>=18&&max-min<=100,'visible restrained mineral variation');
  assert.ok(new Set(variation).size>4,'nonflat normal map');
});
test('stone generation rejects unbounded geometry textures',()=>{
  for(const n of [32,127,1024,256.5])assert.throws(()=>buildStratifiedStoneTexels(n),RangeError);
});
