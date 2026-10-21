
/**
 * Three distinct destinations with authored procedural material studies.
 * These are intentionally shader-only, zero-network and deterministic.
 * The final art direction will be replaced by licensed art assets / GLB.
 */
export const VISTA_VERTEX = `
  varying vec2 vUv;
  void main() {
    vUv = uv;
    gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
  }
`;

export const VISTA_FRAGMENT = `
  uniform float uTime;
  uniform float uFocus;
  uniform float uMode;
  uniform vec3 uTint;
  varying vec2 vUv;

  float hash(vec2 v) {return fract(sin(dot(v,vec2(127.1,311.7)))*43758.5453);}
  float noise(vec2 v) {
    vec2 i=floor(v),f=fract(v);
    f=f*f*(3.0-2.0*f);
    return mix(mix(hash(i),hash(i+vec2(1.,0.)),f.x),
               mix(hash(i+vec2(0.,1.)),hash(i+vec2(1.,1.)),f.x),f.y);
  }
  float fbm(vec2 v) {
    float n=0.,a=.5;
    for(int i=0;i<4;i++) {n+=noise(v)*a;v=v*2.05+17.2;a*=.5;}
    return n;
  }
  float disk(vec2 p,vec2 center,float r) {
    return 1.-smoothstep(r-.008,r+.008,length(p-center));
  }
  float box(vec2 p, vec2 center, vec2 halfSize) {
    vec2 d=abs(p-center)-halfSize;
    return 1.-smoothstep(.0,.015,length(max(d,0.))+min(max(d.x,d.y),0.));
  }
  vec3 chess(vec2 uv) {
    // Deep gold coronation hall; the king is silhouette, not a UI glyph.
    float rays = pow(max(0.,1.-abs(uv.x-.52)*1.9),3.);
    float haze = fbm(uv*vec2(4.,7.));
    vec3 c = mix(vec3(.012,.021,.035),vec3(.27,.19,.095),uv.y*.32+rays*.40);
    c += vec3(.22,.14,.045)*rays*pow(max(0.,uv.y),2.);
    float horizon = .43;
    if(uv.y < horizon) {
      float depth=1.0/max(.025,horizon-uv.y);
      float xx=(uv.x-.5)*depth*.35;
      float yy=depth*.23;
      float checker=mod(floor(xx)+floor(yy),2.);
      vec3 stone=mix(vec3(.04,.05,.06),vec3(.26,.20,.13),checker);
      float gridLines=step(.94,fract(abs(xx)))+step(.94,fract(yy));
      c=mix(c,stone,clamp((horizon-uv.y)*4.0,0.,.87));
      c+=vec3(.12,.095,.053)*gridLines*.15;
    }
    float king=0.;
    king=max(king,box(uv,vec2(.50,.39),vec2(.105,.017)));
    king=max(king,box(uv,vec2(.50,.46),vec2(.078,.050)));
    king=max(king,box(uv,vec2(.50,.55),vec2(.055,.10)));
    king=max(king,disk(uv,vec2(.5,.655),.045));
    king=max(king,box(uv,vec2(.5,.71),vec2(.010,.078)));
    king=max(king,box(uv,vec2(.5,.735),vec2(.055,.009)));
    float aura = exp(-length((uv-vec2(.5,.59))*vec2(2.0,1.4))*5.);
    c+=vec3(.38,.25,.07)*aura*.44;
    c=mix(c,vec3(.015,.019,.028),king*.92);
    c+=uTint*haze*.022;
    return c;
  }
  vec3 chronicles(vec2 uv) {
    // Receding dungeon arches, molten torch pools and slate shadows.
    float distanceToCenter=abs(uv.x-.5);
    float mist=fbm(uv*vec2(5.,8.)+vec2(0.,uTime*.008));
    vec3 c=mix(vec3(.018,.025,.035),vec3(.18,.085,.046),uv.y*.40+mist*.24);
    float corridor=1.-smoothstep(.20,.48,distanceToCenter);
    c*=mix(.40,1.,corridor);
    // Three nested stone vaults: a real sense of a passage beyond the door.
    for(int i=0;i<4;i++) {
      float d=float(i), width=.43-d*.075;
      float roof=.78-d*.065-.26*pow(abs((uv.x-.5)/width),2.);
      float ring=1.-smoothstep(.012,.032,abs(abs(uv.x-.5)-width));
      float crown=1.-smoothstep(.010,.026,abs(uv.y-roof));
      float gate=step(.14+d*.05,uv.y)*step(uv.y,roof+.04);
      c+=vec3(.19,.12,.083)*(ring*gate+crown*step(uv.y,.83))* (.51-d*.095);
    }
    float steps=0.;
    if(uv.y<.36){
      float depth=1./max(.04,.36-uv.y);
      steps=step(.84,fract(depth*.49))*step(abs(uv.x-.5),(.43-uv.y)*.7);
      c+=vec3(.20,.14,.088)*steps*.20;
    }
    vec2 flameA=(uv-vec2(.20,.53))*vec2(2.,1.);
    vec2 flameB=(uv-vec2(.80,.53))*vec2(2.,1.);
    float flames=exp(-length(flameA)*12.)+exp(-length(flameB)*12.);
    c+=vec3(.95,.40,.085)*flames*(.88+.12*sin(uTime*1.8));
    c+=vec3(.26,.1,.025)*mist*.11;
    return c;
  }
  vec3 starfield(vec2 uv) {
    // A bridge window onto a nebula, planet and distant stellar dust.
    vec2 p=uv-.5;
    float nebula=fbm(uv*vec2(3.4,4.6)+vec2(uTime*.007,0.));
    float bands=pow(max(0.,1.-abs(p.y+p.x*.24)*3.),3.);
    vec3 c=vec3(.007,.023,.043);
    c+=vec3(.05,.25,.32)*nebula*bands*.61;
    c+=vec3(.13,.08,.27)*pow(fbm(uv*6.5),2.)*.36;
    float planet=disk(uv,vec2(.58,.58),.215);
    float daylight=disk(uv,vec2(.66,.62),.192);
    vec3 sphere=mix(vec3(.035,.06,.09),vec3(.18,.43,.48),uv.y*.28+nebula*.45);
    c=mix(c,sphere,planet*.92);
    c+=vec3(.53,.84,.86)*planet*(1.-daylight)*.40;
    float atmosphere=exp(-abs(length(uv-vec2(.58,.58))-.219)*75.);
    c+=vec3(.07,.32,.44)*atmosphere*.48;
    vec2 starGrid=floor(uv*vec2(58.,90.));
    float localStar=step(.994,hash(starGrid));
    vec2 sparkle=fract(uv*vec2(58.,90.))-.5;
    float stars=localStar*(1.-smoothstep(.018,.12,length(sparkle)));
    c+=vec3(.7,.88,1.)*stars*.85*(1.-planet);
    // Subtle starship-window sill in the foreground.
    c=mix(c,vec3(.008,.017,.03),1.-smoothstep(.12,.15,uv.y));
    return c;
  }
  void main() {
    vec2 uv=vUv;
    float blur=noise(uv*24.+uTime*.006);
    vec3 color=vec3(0.);
    if(uMode<.5) color=chess(uv);
    else if(uMode<1.5) color=chronicles(uv);
    else color=starfield(uv);
    float focusBoost=.80+uFocus*.28;
    color*=focusBoost;
    color+=uTint*blur*.018;
    float edge=length(vec2((uv.x-.5)*1.5,(uv.y-.51)*.8));
    float vignette=1.-smoothstep(.44,.76,edge);
    float alpha=(.89+.10*uFocus)*vignette;
    gl_FragColor=vec4(color,clamp(alpha,0.,1.));
    #include <tonemapping_fragment>
    #include <colorspace_fragment>
  }
`;
