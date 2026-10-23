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
      const waviness=Math.sin(y*.063)*7.0+Math.sin(y*.17)*1.8;
      const grain=Math.sin((x+waviness)*.21)*.10+
        Math.sin((x+waviness)*.83)*.036;
      const knots=Math.exp(-((x-size*.71)**2/(size*size*.003)+
                           (y-size*.48)**2/(size*size*.020)));
      const variance=grain*91+grit*21-knots*34;
      color=[210+variance,186+variance*.84,151+variance*.66];
    } else {
      const mineral=Math.sin(x*.031+y*.027)*.065+
        Math.cos(x*.077-y*.041)*.033+
        Math.sin(x*.15+y*.093)*.022;
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
