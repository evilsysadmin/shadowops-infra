import {test} from 'node:test';
import assert from 'node:assert/strict';
import {makeCarvedCorniceGeometry,CORNICE_SECTION} from '../art/carvedCornice.mjs';

test('continuous carved crown has a multi-depth sculpted section, not a flat box',()=>{
  const geometry=makeCarvedCorniceGeometry();
  try {
    const {min,max}=geometry.boundingBox;
    assert.ok(Math.abs(min.x+6)<.02&&Math.abs(max.x-6)<.02,'spans all three arch heads');
    assert.ok(min.y>3.85 && max.y<4.15,'stays in the authored upper architectural zone');
    assert.ok(min.z> -1.60 && max.z< -1.02,'stepped crown remains behind glass targets');
    assert.ok(CORNICE_SECTION.length>=9,'actual stepped undercut profile');
    assert.ok(new Set(CORNICE_SECTION.map(p=>p[0])).size>=7,'multiple true Z-depth levels');
    assert.ok(geometry.getAttribute('position').count/3<1200,'bounded sculpted triangle budget');
    const normals=geometry.getAttribute('normal').array;
    assert.ok([...normals].every(Number.isFinite),'finite PBR surface normals');
  } finally {
    geometry.dispose();
  }
});

test('out-of-budget cornice lengths are rejected',()=>{
  assert.throws(()=>makeCarvedCorniceGeometry(25),RangeError);
  assert.throws(()=>makeCarvedCorniceGeometry(1),RangeError);
  assert.throws(()=>makeCarvedCorniceGeometry(NaN),RangeError);
});
