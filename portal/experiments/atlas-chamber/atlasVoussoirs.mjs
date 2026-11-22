import * as THREE from 'three';

// Build proper wedge-faced arch stones (voussoirs) along the two existing
// spring-to-apex curves. Adjacent stones have deliberate mortar-width joints.
// One non-indexed BufferGeometry keeps the 14 solid blocks in ONE draw call.
export function makeAtlasVoussoirGeometry(curves) {
  if(!Array.isArray(curves)||curves.length!==2 ||
    curves.some(curve=>typeof curve?.getPoint!=='function' ||
      typeof curve?.getTangent!=='function'))
    throw new TypeError('The two spring-to-crown curves are required');
  const piecesPerHalf=7;
  const halfBand=.113;
  const jointFraction=.035;
  const frontZ=-4.72,backZ=-5.01;
  const positions=[],uvs=[];
  const add=(vertex,plane)=>{
    positions.push(vertex.x,vertex.y,vertex.z);
    const u=plane==='yz'?vertex.y:vertex.x;
    const v=plane==='xy'?vertex.y:vertex.z;
    uvs.push(u*.36,v*.36);
  };
  const quad=(a,b,c,d,plane)=>{
    for(const vertex of [a,b,c,a,c,d])add(vertex,plane);
  };
  const end=(point,normal,offset,z)=>
    new THREE.Vector3(point.x+normal.x*offset,point.y+normal.y*offset,z);
  for(const curve of curves){
    for(let i=0;i<piecesPerHalf;i++){
      // Leave a measured joint on BOTH ends. No faux line overlay.
      const start=(i+jointFraction)/piecesPerHalf;
      const finish=(i+1-jointFraction)/piecesPerHalf;
      const p=curve.getPoint(start),q=curve.getPoint(finish);
      const tp=curve.getTangent(start).normalize();
      const tq=curve.getTangent(finish).normalize();
      const np=new THREE.Vector3(-tp.y,tp.x,0).normalize();
      const nq=new THREE.Vector3(-tq.y,tq.x,0).normalize();
      const a=end(p,np,-halfBand,frontZ);
      const b=end(q,nq,-halfBand,frontZ);
      const c=end(q,nq,halfBand,frontZ);
      const d=end(p,np,halfBand,frontZ);
      const A=end(p,np,-halfBand,backZ);
      const B=end(q,nq,-halfBand,backZ);
      const C=end(q,nq,halfBand,backZ);
      const D=end(p,np,halfBand,backZ);
      // Front/back, extrados/intrados and both end-grain joints. The tangent
      // normals make genuine tapering masonry, not rotated rectangular boxes.
      quad(a,b,c,d,'xy');
      quad(A,D,C,B,'xy');
      quad(d,c,C,D,'xz');
      quad(b,a,A,B,'xz');
      quad(a,d,D,A,'yz');
      quad(c,b,B,C,'yz');
    }
  }
  const geometry=new THREE.BufferGeometry();
  geometry.setAttribute('position',new THREE.Float32BufferAttribute(positions,3));
  geometry.setAttribute('uv',new THREE.Float32BufferAttribute(uvs,2));
  geometry.computeVertexNormals();
  geometry.computeBoundingBox();
  geometry.computeBoundingSphere();
  geometry.userData.voussoirCount=curves.length*piecesPerHalf;
  return geometry;
}
