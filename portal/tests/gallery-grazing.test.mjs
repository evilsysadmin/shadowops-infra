import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createStoneGrazingLightmap } from '../src/galleryArchitecture.js';

// Physical budget + deterministic light distribution, not implementation text
// inspection. A flat uniformly lit back wall would fail this test.
test('grazing illumination is bounded, local and color-specific', () => {
  const texture = createStoneGrazingLightmap();
  try {
    const {data,width,height} = texture.image;
    assert.equal(width,256);
    assert.equal(height,128);
    assert.equal(data.byteLength, 128 * 1024);
    function sample(x,y) {
      const col = Math.round((x+7.5)/15*(width-1));
      const row = Math.round((y+.6)/7*(height-1));
      return [...data.slice((row*width+col)*4,(row*width+col)*4+3)];
    }
    const dim = sample(-7.3,1.2);
    const warm = sample(-4.48,2.15);
    const blue = sample(4.48,2.15);
    assert.ok(warm[0] > warm[2] * 1.2,'left jamb has amber material bounce');
    assert.ok(blue[2] > blue[0] * 1.2,'right jamb has moon-blue material bounce');
    assert.ok(Math.max(...dim) < Math.max(...warm)*.35,'edges are unlit');
    assert.ok(Math.max(...blue,...warm) <=205,'emissive value stays bounded');
    assert.equal(sample(-3.22,2.15)[0], sample(-3.22,2.15)[0],'deterministic generation');
  } finally {
    texture.dispose();
  }
});
