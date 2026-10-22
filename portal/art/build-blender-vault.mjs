import {spawnSync} from 'node:child_process';
import {readFile, rename, mkdir, unlink} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import {writeManifest} from './glbWriter.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const outDir=path.join(root,'public','art');
const draft=path.join(outDir,'celestial-vault-draft.glb');
await mkdir(outDir,{recursive:true});
const isRequired=process.env.REQUIRE_BLENDER_ART==='1';
const exe=process.env.BLENDER_BINARY||'blender';
const args=['--background','--factory-startup','--python-exit-code','7','--python',
  path.join(root,'art','blender','celestial_vault.py'),'--',draft];
const run=spawnSync(exe,args,{encoding:'utf8',timeout:210000,
  maxBuffer:8*1024*1024});
if(run.stdout)console.log('Blender stdout:\n'+run.stdout.slice(-4500));
if(run.stderr)console.warn('Blender stderr:\n'+run.stderr.slice(-4500));
if(run.error||run.status!==0) {
  const reason=run.error?.message||run.stderr||run.stdout||('exit '+run.status);
  if(isRequired)throw new Error('Mandatory Blender celestial-vault export failed: '+reason.slice(-2500));
  console.warn('Optional local Blender artwork skipped: '+String(reason).slice(-350));
  await writeManifest('vaultAsset.generated.mjs',{
    VAULT_ASSET:null,VAULT_SHA256:null,VAULT_BYTES:0,
  });
} else {
  const glb=await readFile(draft);
  if(glb.length>1500000)throw Error('Blender vault GLB exceeds 1.5 MB budget');
  if(glb.readUInt32LE(0)!==0x46546c67||glb.readUInt32LE(4)!==2||
    glb.readUInt32LE(8)!==glb.length)throw Error('Invalid GLB 2.0 export');
  const len=glb.readUInt32LE(12);
  const gltf=JSON.parse(glb.subarray(20,20+len).toString());
  if(!gltf.meshes?.length||gltf.materials?.length!==3)throw Error('Missing DCC geometry or materials');
  const sha=createHash('sha256').update(glb).digest('hex');
  const filename='celestial-vault-'+sha.slice(0,12)+'.glb';
  await rename(draft,path.join(outDir,filename));
  await writeManifest('vaultAsset.generated.mjs',{
    VAULT_ASSET:'/art/'+filename,VAULT_SHA256:sha,VAULT_BYTES:glb.length,
  });
  console.log('Authored Blender vault: '+filename+', '+glb.length+' bytes, '+gltf.meshes.length+' mesh(es)');
}
