import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {
 GALLERY_FRAME_ASSET,GALLERY_FRAME_SHA256,GALLERY_FRAME_TRIANGLES,GALLERY_FRAME_BYTES,
} from '../src/galleryFrame.generated.mjs';

test('authored gallery GLB is content-addressed, bounded and has 3 PBR parts',async()=>{
 assert.match(GALLERY_FRAME_ASSET,/^\/art\/gallery-frame-[a-f0-9]{12}\.glb$/);
 const blob=await readFile(new URL('../public'+GALLERY_FRAME_ASSET,import.meta.url));
 assert.equal(blob.readUInt32LE(0),0x46546c67);
 assert.equal(blob.readUInt32LE(4),2);
 assert.equal(blob.readUInt32LE(8),blob.length);
 assert.ok(blob.length<1650000);
 assert.equal(blob.length,GALLERY_FRAME_BYTES);
 assert.equal(createHash('sha256').update(blob).digest('hex'),GALLERY_FRAME_SHA256);
 const json=JSON.parse(blob.subarray(20,20+blob.readUInt32LE(12)).toString());
 assert.equal(json.asset.version,'2.0');
 assert.equal(json.meshes.length,1);
 assert.equal(json.meshes[0].primitives.length,3);
 assert.equal(json.materials.length,3);
 assert.ok(json.meshes[0].primitives.every(p=>p.mode===4));
 assert.ok(GALLERY_FRAME_TRIANGLES>500 && GALLERY_FRAME_TRIANGLES<62000);
});
