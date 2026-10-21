import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { ARMILLARY_ASSET, ARMILLARY_SHA256 } from '../src/armillaryAsset.generated.mjs';

test('authored model: GLB v2, merged primitives, content hash and size budget',async()=>{
 assert.match(ARMILLARY_ASSET,/^\/art\/armillary-[a-f0-9]{12}\.glb$/);
 const data=await readFile(new URL('../public'+ARMILLARY_ASSET,import.meta.url));
 assert.ok(data.length<950000);
 assert.equal(data.readUInt32LE(0),0x46546c67);
 assert.equal(data.readUInt32LE(4),2);
 assert.equal(data.readUInt32LE(8),data.length);
 const jsonLength=data.readUInt32LE(12);
 assert.equal(data.readUInt32LE(16),0x4e4f534a);
 const gltf=JSON.parse(data.subarray(20,20+jsonLength).toString());
 assert.equal(gltf.asset.version,'2.0');
 assert.equal(gltf.meshes[0].primitives.length,3);
 assert.equal(gltf.materials.length,3);
 assert.equal(gltf.buffers.length,1);
 assert.ok(gltf.accessors.some(a=>a.type==='VEC3'));
 const digest=createHash('sha256').update(data).digest('hex');
 assert.equal(digest,ARMILLARY_SHA256);
 assert.ok(ARMILLARY_ASSET.includes(digest.slice(0,12)));
});
