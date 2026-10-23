import './atlas.css';
import {worldsForHost,worldById,isLaunchable,portalEnvironmentForHost} from '../../src/catalog.mjs';

const stage=document.getElementById('atlas-viewport');
const status=document.getElementById('atlas-stage-status');
const shell=document.getElementById('atlas-shell');
const enter=document.getElementById('atlas-enter');
const selected=worldById('chess',worldsForHost(window.location.hostname));
const environment=portalEnvironmentForHost(window.location.hostname);
shell.dataset.environment=environment;

if(isLaunchable(selected)){
  const link=document.createElement('a');
  link.className='atlas-enter';
  link.textContent='Entrar en Chess Studio ↗';
  link.href=selected.destination;
  link.rel='noopener noreferrer';
  link.setAttribute('aria-label','Abrir Chess Studio en '+(environment==='staging'?'staging':'producción'));
  enter.appendChild(link);
}else{
  const text=document.createElement('span');
  text.className='atlas-enter atlas-enter-disabled';
  text.textContent='Concepto en desarrollo — entrada desactivada';
  enter.appendChild(text);
}
document.querySelector('.atlas-seal-current')?.addEventListener('click',()=>{
  const link=enter.querySelector('a');
  if(link)link.focus();
  else document.getElementById('atlas-title')?.scrollIntoView({block:'nearest'});
});

let mounted=null;
function fallback(reason){
  stage.dataset.scene='unavailable';
  status.textContent='SIN WEBGL · ESTUDIO DE CONCEPTO';
  stage.dataset.reason=reason;
}
async function load(){
  if(!window.WebGLRenderingContext){fallback('unsupported');return;}
  try{
    const {mountAtlasChamber}=await import('./atlasWorld.mjs');
    mounted=mountAtlasChamber(stage);
    const observer=new MutationObserver(()=>{
      if(stage.dataset.renderState==='ready'){
        stage.dataset.scene='ready';
        status.textContent=environment==='preview'?'CONCEPTO NO PUBLICADO':'ATLAS · PROTOTIPO';
        observer.disconnect();
      }
    });
    observer.observe(stage,{attributes:true,attributeFilter:['data-render-state']});
    if(stage.dataset.renderState==='ready'){
      stage.dataset.scene='ready';
      status.textContent=environment==='preview'?'CONCEPTO NO PUBLICADO':'ATLAS · PROTOTIPO';
      observer.disconnect();
    }
    stage.querySelector('canvas')?.addEventListener('webglcontextlost',event=>{
      event.preventDefault();
      mounted?.destroy();mounted=null;
      fallback('context-lost');
    },{once:true});
  }catch(err){
    console.warn('Atlas Chamber falls back to its static, accessible layout.',err);
    mounted?.destroy();mounted=null;fallback('failed');
  }
}
window.addEventListener('pagehide',()=>mounted?.destroy(),{once:true});
void load();
