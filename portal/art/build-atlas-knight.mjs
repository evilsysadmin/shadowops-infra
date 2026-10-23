import {spawnSync} from 'node:child_process';
import {readFile,mkdir,rename} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import {writeManifest} from './glbWriter.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const output=path.join(root,'public','art');
await mkdir(output,{recursive:true});
const draft=path.join(output,'atlas-knight-draft.glb');
const required=process.env.REQUIRE_BLENDER_ART==='1';
const processResult=spawnSync(process.env.BLENDER_BINARY||'blender',[
  '--background','--factory-startup','--python-exit-code','7',
  '--python',path.join(root,'art','blender','atlas_knight.py'),'--',draft,
],{encoding:'utf8',timeout:150000,maxBuffer:5*1024*1024});
if(processResult.stdout)console.log(processResult.stdout.slice(-1800));
if(processResult.stderr)console.warn(processResult.stderr.slice(-1600));
if(processResult.error || processResult.status!==0){
  const why=String(processResult.error?.message||processResult.stderr||processResult.stdout||
    ('Blender exited '+processResult.status));
  if(required)throw Error('Mandatory authored Atlas knight failed: '+why.slice(-2000));
  console.warn('Atlas knight optional on workstations without Blender: '+why.slice(-300));
  await writeManifest('atlasKnightAsset.generated.mjs',{
    ATLAS_KNIGHT_ASSET:null,ATLAS_KNIGHT_SHA256:null,ATLAS_KNIGHT_BYTES:0,
  });
}else{
  const glb=await readFile(draft);
  if(glb.length<10000 || glb.length>450000)throw Error('Atlas knight GLB size budget: '+glb.length);
  if(glb.readUInt32LE(0)!==0x46546c67 || glb.readUInt32LE(4)!==2 ||
      glb.readUInt32LE(8)!==glb.length)throw Error('Invalid Atlas knight GLB 2.0');
  const json=JSON.parse(glb.subarray(20,20+glb.readUInt32LE(12)).toString());
  if(json.materials?.length!==3 || json.meshes?.length!==3)
    throw Error('The sculpted Atlas knight must have three joined materials');
  const positions=json.meshes.flatMap(m=>m.primitives).map(p=>json.accessors[p.attributes.POSITION]);
  if(positions.some(p=>p.count>25000) ||
     !positions.some(p=>p.max?.[1]>1.20) ||
     !positions.some(p=>p.min?.[1]<.08))
    throw Error('Atlas knight has missing sculptural detail or wrong Y-up orientation');
  const sha=createHash('sha256').update(glb).digest('hex');
  const file='atlas-knight-'+sha.slice(0,12)+'.glb';
  await rename(draft,path.join(output,file));
  await writeManifest('atlasKnightAsset.generated.mjs',{
    ATLAS_KNIGHT_ASSET:'/art/'+file,ATLAS_KNIGHT_SHA256:sha,ATLAS_KNIGHT_BYTES:glb.length,
  });
  console.log('Atlas hand-sculpted knight: '+file+' / '+glb.length+' bytes');
}
