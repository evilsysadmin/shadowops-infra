import {spawnSync} from 'node:child_process';
import {readFile,writeFile,mkdir,rename} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import {writeManifest} from './glbWriter.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
// Keep this GLB strictly in the local experiment, never the root Pages build.
const output=path.join(root,'experiments','atlas-chamber','compiled');
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
    throw Error('Atlas knight has missing sculptural detail or wrong Y-up orientation: '+
      JSON.stringify(positions.map(p=>({count:p.count,min:p.min,max:p.max}))));
  // Blender may emit identical, identically wound triangles in a different
  // iteration order across exports. Canonicalize *index order only* before
  // hashing; vertex buffers, normals, winding and the rendered mesh are intact.
  const binaryStart=20+glb.readUInt32LE(12)+8;
  for(const mesh of json.meshes){
    for(const primitive of mesh.primitives){
      if((primitive.mode??4)!==4)throw Error('Expected indexed GLB triangles');
      const accessor=json.accessors[primitive.indices];
      const view=json.bufferViews[accessor?.bufferView];
      if(!accessor || !view || accessor.count%3 || view.byteStride)
        throw Error('Cannot canonicalize non-packed triangle index accessor');
      const width=accessor.componentType===5123?2:accessor.componentType===5125?4:0;
      if(!width)throw Error('Unsupported triangle index component type');
      const offset=binaryStart+(view.byteOffset||0)+(accessor.byteOffset||0);
      if(offset+width*accessor.count>glb.length)
        throw Error('Triangle index accessor exceeds GLB');
      const read=i=>width===2?glb.readUInt16LE(i):glb.readUInt32LE(i);
      const write=(i,value)=>width===2?glb.writeUInt16LE(value,i):glb.writeUInt32LE(value,i);
      const triangles=[];
      for(let i=0;i<accessor.count;i+=3){
        const base=offset+i*width;
        const t=[read(base),read(base+width),read(base+width*2)];
        while(t[0]>Math.min(...t))t.push(t.shift()); // cyclic: preserve winding
        triangles.push(t);
      }
      triangles.sort((a,b)=>a[0]-b[0]||a[1]-b[1]||a[2]-b[2]);
      for(let i=0;i<triangles.length;i++){
        for(let j=0;j<3;j++)write(offset+(i*3+j)*width,triangles[i][j]);
      }
    }
  }
  await writeFile(draft,glb);
  const sha=createHash('sha256').update(glb).digest('hex');
  const file='atlas-knight-'+sha.slice(0,12)+'.glb';
  await rename(draft,path.join(output,file));
  await writeManifest('atlasKnightAsset.generated.mjs',{
    ATLAS_KNIGHT_ASSET:'/experiments/atlas-chamber/compiled/'+file,ATLAS_KNIGHT_SHA256:sha,ATLAS_KNIGHT_BYTES:glb.length,
  });
  console.log('Atlas hand-sculpted knight: '+file+' / '+glb.length+' bytes');
}
