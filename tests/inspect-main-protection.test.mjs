import test from 'node:test';
import assert from 'node:assert/strict';
import {PR_CHECKS, diagnoseMainProtection, inspectMain} from '../scripts/inspect-main-protection.mjs';

const match = {
  id: 25198769, name: 'Protect main', target: 'branch',
  enforcement: 'active',
  conditions: {ref_name:{exclude:[],include:['~DEFAULT_BRANCH']}},
  rules: [
    {type:'deletion'}, {type:'non_fast_forward'}, {type:'pull_request'},
    {type:'required_status_checks',
     parameters:{required_status_checks:PR_CHECKS.map(context=>({context}))}},
  ]
};

test('matches effective protected main and precisely the four PR checks',()=>{
  const result=diagnoseMainProtection({protected:true},[match]);
  assert.equal(result.verified,true);
  assert.deepEqual(result.missingChecks,[]);
  assert.deepEqual(result.matchingRulesets,['Protect main']);
});

test('detects existing active but untargeted empty ruleset',()=>{
  const empty={...match,
    conditions:{ref_name:{exclude:[],include:[]}},
    rules:match.rules.map(rule=>rule.type==='required_status_checks'?
      {...rule,parameters:{required_status_checks:[]}}:rule)};
  const result=diagnoseMainProtection({protected:false},[empty]);
  assert.equal(result.verified,false);
  assert.match(result.blockers.join(' '),/no active branch ruleset targets main/);
  assert.deepEqual(result.missingChecks,PR_CHECKS);
  assert.match(result.blockers.join(' '),/main.protected=false/);
});

test('rejects disabled enforcement, wrong target, missing PR rules or a missing check',()=>{
  for(const item of [
    {...match,enforcement:'disabled'},
    {...match,target:'tag'},
    {...match,conditions:{ref_name:{include:['refs/heads/dev']}}},
    {...match,rules:match.rules.filter(rule=>rule.type!=='pull_request')},
    {...match,rules:match.rules.map(rule=>rule.type==='required_status_checks'?
      {...rule,parameters:{required_status_checks:PR_CHECKS.slice(1).map(context=>({context}))}}:rule)}
  ]) {
    assert.equal(diagnoseMainProtection({protected:true},[item]).verified,false);
  }
  assert.equal(diagnoseMainProtection({protected:false},[match]).verified,false);
});

test('queries authoritative branch and individual active ruleset details',async()=>{
  const seen=[];
  const fetchImpl=async(url,options)=>{
    const path=new URL(url).pathname;
    seen.push({path,redirect:options.redirect});
    let response;
    if(path.endsWith('/branches/main')) response={protected:true};
    else if(path.endsWith('/rulesets')) response=[{id:25198769,target:'branch',enforcement:'active'}];
    else if(path.endsWith('/rulesets/25198769')) response=match;
    else throw new Error('Unexpected URL '+url);
    return {ok:true,json:async()=>response};
  };
  const result=await inspectMain({fetchImpl});
  assert.equal(result.verified,true);
  assert.equal(seen.length,3);
  assert.ok(seen.every(x=>x.redirect==='error'));
});

test('fails closed on denied GitHub API reads and invalid responses',async()=>{
  await assert.rejects(inspectMain({fetchImpl:async()=>({ok:false,status:403})}),/403/);
  await assert.rejects(inspectMain({fetchImpl:async()=>({ok:true,json:async()=>({})})}),/rulesets list/);
});
