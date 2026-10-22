import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {VAULT_ASSET,VAULT_SHA256,VAULT_BYTES} from '../src/vaultAsset.generated.mjs';

test('Blender-authored celestial vault is a bounded content-addressed GLB with PBR materials',async()=>{
  if(!VAULT_ASSET){
    assert.notEqual(process.env.REQUIRE_BLENDER_ART,'1','CI must not silently skip mandatory Blender asset');
    return;
  }
  assert.match(VAULT_ASSET,/^\/art\/celestial-vault-[a-f0-9]{12}\.glb$/);
  const glb=await readFile(new URL('../public'+VAULT_ASSET,import.meta.url));
  assert.equal(glb.readUInt32LE(0),0x46546c67);
  assert.equal(glb.readUInt32LE(4),2);
  assert.equal(glb.readUInt32LE(8),glb.length);
  assert.ok(glb.length>10000&&glb.length<1500000);
  assert.equal(glb.length,VAULT_BYTES);
  const digest=createHash('sha256').update(glb).digest('hex');
  assert.equal(digest,VAULT_SHA256);
  assert.ok(VAULT_ASSET.includes(digest.slice(0,12)));
  const json=JSON.parse(glb.subarray(20,20+glb.readUInt32LE(12)).toString());
  assert.equal(json.asset.version,'2.0');
  assert.equal(json.materials.length,3);
  assert.ok(json.meshes.length>=1&&json.meshes.length<=3);
  const primitives=json.meshes.flatMap(mesh=>mesh.primitives||[]);
  assert.ok(primitives.length>=3&&primitives.length<=6);
  assert.ok(primitives.every(p=>json.accessors[p.attributes.POSITION]?.count>0));
  // Existing gallery artifact remains three PBR primitives with bounded geometry.
  assert.ok(primitives.every(p=>json.accessors[p.attributes.POSITION].count<85000));
  // Exporter must retain a real Y-up foreground, not only upper wall art.
  const positions=primitives.map(p=>json.accessors[p.attributes.POSITION]).filter(Boolean);
  assert.ok(positions.some(p=>p.min?.[1]<-.1),'floor marquetry reaches the dais');
  assert.ok(positions.some(p=>p.max?.[2]>2.9),'foreground compass is in front of the entrances');
});
