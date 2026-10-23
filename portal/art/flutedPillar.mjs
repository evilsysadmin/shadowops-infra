import * as THREE from 'three';

// A genuinely sculpted, fluted shaft rather than a cylindrical prop with
// painted stripes. The surface profile is stable/deterministic and uses the
// existing honed-stone PBR material and existing authored gallery GLB.
export function makeFlutedPilasterGeometry({
  topRadius = .115,
  bottomRadius = .151,
  height = 2.76,
  flutes = 12,
  grooveDepth = .012,
} = {}) {
  if (grooveDepth <= 0 || grooveDepth >= topRadius * .20 ||
      !Number.isInteger(flutes) || flutes < 6 || flutes > 20) {
    throw new RangeError('Pilaster fluting must remain shallow and bounded');
  }
  const geo = new THREE.CylinderGeometry(topRadius, bottomRadius, height, 96, 8);
  const positions = geo.getAttribute('position');
  const normals = geo.getAttribute('normal');
  const vertex = new THREE.Vector3();
  for (let i = 0; i < positions.count; i++) {
    // Preserve solid top/bottom caps. Displace only the cylindrical side.
    if (Math.abs(normals.getY(i)) > .5) continue;
    vertex.fromBufferAttribute(positions, i);
    const angle = Math.atan2(vertex.z, vertex.x);
    // Rounded chisel-cut channels separated by broad stone ribs.
    const shape = Math.pow((1 + Math.cos(flutes * angle)) * .5, 4);
    const radius = Math.hypot(vertex.x, vertex.z);
    const target = radius - grooveDepth * shape;
    const factor = target / radius;
    positions.setXYZ(i, vertex.x * factor, vertex.y, vertex.z * factor);
  }
  positions.needsUpdate = true;
  geo.computeVertexNormals();
  geo.computeBoundingBox();
  return geo;
}
