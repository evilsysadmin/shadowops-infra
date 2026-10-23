import {test} from 'node:test';
import assert from 'node:assert/strict';
import {makeFlutedPilasterGeometry} from '../art/flutedPillar.mjs';

test('authored pilaster has actual twelve-channel stone relief, not texture-only stripes', () => {
  const shaft=makeFlutedPilasterGeometry();
  try {
    const positions=shaft.getAttribute('position');
    const middle=[];
    for(let i=0;i<positions.count;i++){
      if (Math.abs(positions.getY(i)) < 1e-6) {
        middle.push(Math.hypot(positions.getX(i),positions.getZ(i)));
      }
    }
    assert.ok(middle.length >= 96,'sample a whole radial cross-section');
    const spread=Math.max(...middle)-Math.min(...middle);
    assert.ok(spread >= .011 && spread <= .015,
      'deep enough for genuine sculpting, but still a restrained stone channel');
    assert.equal(shaft.boundingBox.min.y,-1.38);
    assert.equal(shaft.boundingBox.max.y,1.38);
    assert.ok(shaft.index.count/3 < 2500,'bounded pilaster triangle cost');
  } finally {shaft.dispose();}
});

test('fluting cannot become a high-density ornament or tear the shaft',()=>{
  assert.throws(()=>makeFlutedPilasterGeometry({grooveDepth:.03}),RangeError);
  assert.throws(()=>makeFlutedPilasterGeometry({flutes:50}),RangeError);
  assert.throws(()=>makeFlutedPilasterGeometry({flutes:2}),RangeError);
});
