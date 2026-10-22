import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { WORLD_RELICS } from '../src/worldRelics.generated.mjs';

test('three distinct source-authored, content-addressed GLB world relics',async()=>{
 const ids=['chess','chronicles','star'];
 assert.deepEqual(Object.keys(WORLD_RELICS),ids);
 const seen=new Set();
 for(const id of ids){
   const relic=WORLD_RELICS[id];
   assert.match(relic.url,new RegExp('^/art/relic-'+id+'-[a-f0-9]{12}\\.glb$'));
   assert.ok(relic.bytes<425000,'relic GLB size budget');
   const bin=await readFile(new URL('../public'+relic.url,import.meta.url));
   assert.equal(bin.length,relic.bytes);
   assert.equal(bin.readUInt32LE(0),0x46546c67);
   assert.equal(bin.readUInt32LE(4),2);
   assert.equal(bin.readUInt32LE(8),bin.length);
   const gltf=JSON.parse(bin.subarray(20,20+bin.readUInt32LE(12)).toString());
   assert.equal(gltf.asset.version,'2.0');
   assert.equal(gltf.meshes[0].primitives.length,3);
   assert.ok(gltf.meshes[0].primitives.every(p=>p.mode===4));
   assert.equal(gltf.materials.length,3);
   const hash=createHash('sha256').update(bin).digest('hex');
   assert.equal(hash,relic.sha256);
   assert.ok(relic.url.includes(hash.slice(0,12)));
   assert.ok(relic.triangles>80 && relic.triangles<30000);
   seen.add(hash);
 }
 assert.equal(seen.size,3);
});
