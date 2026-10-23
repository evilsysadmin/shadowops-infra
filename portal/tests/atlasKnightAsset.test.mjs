import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {
 ATLAS_KNIGHT_ASSET,ATLAS_KNIGHT_SHA256,ATLAS_KNIGHT_BYTES
} from '../src/atlasKnightAsset.generated.mjs';

test('Atlas hand-carved knight is a small content-addressed, Y-up DCC sculpture',async()=>{
  if(!ATLAS_KNIGHT_ASSET){
    assert.notEqual(process.env.REQUIRE_BLENDER_ART,'1',
      'CI must never silently skip the authored Atlas knight');
    return;
  }
  assert.match(ATLAS_KNIGHT_ASSET,
    /^\/experiments\/atlas-chamber\/compiled\/atlas-knight-[a-f0-9]{12}\.glb$/);
  const bytes=await readFile(new URL('..'+ATLAS_KNIGHT_ASSET,import.meta.url));
  assert.ok(bytes.length>10000 && bytes.length<450000);
  assert.equal(bytes.length,ATLAS_KNIGHT_BYTES);
  assert.equal(bytes.readUInt32LE(0),0x46546c67);
  assert.equal(bytes.readUInt32LE(4),2);
  assert.equal(bytes.readUInt32LE(8),bytes.length);
  const sha=createHash('sha256').update(bytes).digest('hex');
  assert.equal(sha,ATLAS_KNIGHT_SHA256);
  assert.ok(ATLAS_KNIGHT_ASSET.includes(sha.slice(0,12)));
  const gltf=JSON.parse(bytes.subarray(20,20+bytes.readUInt32LE(12)).toString());
  assert.equal(gltf.asset.version,'2.0');
  assert.equal(gltf.materials.length,3);
  assert.equal(gltf.meshes.length,3,'Three joined materials, not one draw per ornament');
  const props=gltf.meshes.flatMap(m=>m.primitives).map(p=>gltf.accessors[p.attributes.POSITION]);
  assert.ok(props.length>=3 && props.length<=4);
  assert.ok(props.every(a=>a.count>0 && a.count<25000));
  assert.ok(props.some(a=>a.min?.[1]<.08 && a.max?.[1]>1.20),
    'pedestal and tall hand-shaped ears physically present in Y-up scene');
  assert.ok(props.some(a=>a.min?.[0]<-.25 && a.max?.[0]>.28),
    'horse silhouette has a body and distinct muzzle, not a thin vertical rod');
});
