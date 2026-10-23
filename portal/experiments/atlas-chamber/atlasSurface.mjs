import * as THREE from 'three';

// Small, original, deterministic surface albedo. Adds readable grain to the
// authored wood and uneven mineral patina to the chamber's real stone blocks;
// no stock images, fetched assets, shader passes or extra draw calls.
export function makeAtlasSurfaceTexels(kind='wood',size=256){
  if(!['wood','stone'].includes(kind)||!Number.isInteger(size)||size<64||size>512)
    throw new RangeError('Atlas material type or square texel budget invalid');
  const data=new Uint8Array(size*size*4);
  const hash=(x,y)=>{
    let v=Math.imul(x|0,374761393)+Math.imul(y|0,668265263);
    v=Math.imul(v^(v>>>13),1274126177);
    return ((v^(v>>>16))>>>0)/4294967295;
  };
  const clamp=v=>Math.min(255,Math.max(0,Math.round(v)));
  for(let y=0;y<size;y++)for(let x=0;x<size;x++){
    const j=(y*size+x)*4;
    const grit=hash(x,y)-.5;
    let color;
    if(kind==='wood'){
      const phase=2*Math.PI/size;
      const waviness=Math.sin(y*phase)*7.0+Math.sin(y*phase*3)*1.8;
      const grain=Math.sin((x+waviness)*phase*9)*.10+
        Math.sin((x+waviness)*phase*41)*.036;
      const dx=Math.min(Math.abs(x-size*.71),size-Math.abs(x-size*.71));
      const dy=Math.min(Math.abs(y-size*.48),size-Math.abs(y-size*.48));
      const knots=Math.exp(-(dx*dx/(size*size*.003)+
                             dy*dy/(size*size*.020)));
      const variance=grain*91+grit*21-knots*34;
      color=[210+variance,186+variance*.84,151+variance*.66];
    } else {
      const phase=2*Math.PI/size;
      const mineral=Math.sin((2*x+2*y)*phase)*.065+
        Math.cos((5*x-3*y)*phase)*.033+
        Math.sin((13*x+7*y)*phase)*.022;
      const v=mineral*165+grit*24;
      color=[193+v,202+v*.95,208+v*1.08];
    }
    data[j]=clamp(color[0]);data[j+1]=clamp(color[1]);
    data[j+2]=clamp(color[2]);data[j+3]=255;
  }
  return {size,data};
}

export function makeAtlasSurfaceTexture(kind){
  const {size,data}=makeAtlasSurfaceTexels(kind);
  const texture=new THREE.DataTexture(data,size,size,THREE.RGBAFormat);
  texture.colorSpace=THREE.SRGBColorSpace;
  texture.wrapS=texture.wrapT=THREE.RepeatWrapping;
  texture.minFilter=THREE.LinearMipmapLinearFilter;
  texture.magFilter=THREE.LinearFilter;
  texture.generateMipmaps=true;
  texture.needsUpdate=true;
  return texture;
}


/**
 * Derive small tangent-space normal maps from the *same* original albedo.
 * Broad, symmetric finite differences read as worn mineral relief or long
 * wood fibres under light without procedural geometry or another asset fetch.
 * Each RGBA8 256px map is 256 KiB before GPU mipmaps; both < 700 KiB total.
 */
export function makeAtlasNormalTexels(kind='wood',size=256){
  const {data}=makeAtlasSurfaceTexels(kind,size); // shares validation and seed
  const height=(x,y)=>{
    const px=((x%size)+size)%size,py=((y%size)+size)%size;
    const i=(py*size+px)*4;
    return (data[i]*.2126+data[i+1]*.7152+data[i+2]*.0722)/255;
  };
  const result=new Uint8Array(data.length);
  const pack=n=>Math.round(Math.max(0,Math.min(1,n*.5+.5))*255);
  // A 4px derivative avoids turning the 1px-grit albedo into noisy glitter.
  // The same texture-space UVs as the albedo ensure grain is phase-aligned.
  const strength=kind==='wood'?2.25:2.0;
  for(let y=0;y<size;y++)for(let x=0;x<size;x++){
    const dx=(height(x+2,y)-height(x-2,y))*.5*strength;
    const dy=(height(x,y+2)-height(x,y-2))*.5*strength;
    const length=Math.hypot(dx,dy,1);
    const i=(y*size+x)*4;
    result[i]=pack(-dx/length);
    result[i+1]=pack(-dy/length);
    result[i+2]=pack(1/length);
    result[i+3]=255;
  }
  return {size,data:result};
}

export function makeAtlasNormalTexture(kind){
  const {size,data}=makeAtlasNormalTexels(kind);
  const texture=new THREE.DataTexture(data,size,size,THREE.RGBAFormat);
  texture.wrapS=texture.wrapT=THREE.RepeatWrapping;
  texture.minFilter=THREE.LinearMipmapLinearFilter;
  texture.magFilter=THREE.LinearFilter;
  texture.generateMipmaps=true;
  texture.needsUpdate=true;
  return texture; // linear normal data, intentionally not sRGB
}
