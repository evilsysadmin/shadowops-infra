import * as THREE from 'three';

// Original stonework for the continuous observatory crown. A real cross-
// section (sloped weathering cap + stepped cyma + shadow cove) runs the full
// facade width; no flat stacked-box silhouette or extra runtime material.
// Profile coordinates are [scene Z, scene Y], world units.
export const CORNICE_SECTION = Object.freeze([
  [-1.51, 3.905], // inner rear underside
  [-1.51, 4.030],
  [-1.46, 4.098], // sloped cap catches the existing moonlight
  [-1.235, 4.098],
  [-1.196, 4.071],
  [-1.175, 4.030],
  [-1.127, 4.012], // stepped outward-facing architectural moulding
  [-1.102, 3.989],
  [-1.132, 3.959], // undercut shadow line, behind original brass rail
  [-1.190, 3.953],
  [-1.218, 3.905],
]);

export function makeCarvedCorniceGeometry(length = 12) {
  if (!Number.isFinite(length) || length < 4 || length > 16)
    throw new RangeError('Observatory cornice length must stay bounded');
  const section = new THREE.Shape();
  // Local 2D x is minus scene Z: after +90deg Y rotation it becomes scene Z.
  CORNICE_SECTION.forEach(([z,y],i) => {
    if(i === 0) section.moveTo(-z,y);
    else section.lineTo(-z,y);
  });
  section.closePath();
  const geometry = new THREE.ExtrudeGeometry(section,{
    depth:length,
    steps:1,
    curveSegments:1,
    bevelEnabled:true,
    bevelThickness:.006,
    bevelSize:.006,
    bevelSegments:2,
  });
  geometry.rotateY(Math.PI/2);
  geometry.translate(-length/2,0,0);
  geometry.computeBoundingBox();
  return geometry;
}
