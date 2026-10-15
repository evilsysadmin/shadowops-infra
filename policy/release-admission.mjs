import {admitCandidate} from './chronicles.mjs';
import {verifyGithubBuild} from './github-evidence.mjs';
import {verifyRequiredChecks} from './required-checks.mjs';
import {verifyImage} from '../scripts/verify-image-attestation.mjs';
import {accredit} from './accreditation.mjs';

export async function evaluateRelease({candidate,context,runId,token,requiredContexts,fetchImpl,attestationRunner}) {
 const admitted=admitCandidate(candidate,context);
 const github=await verifyGithubBuild({sha:admitted.sha,runId,token,fetchImpl});
 const checks=await verifyRequiredChecks({sha:admitted.sha,token,requiredContexts,fetchImpl});
 const attestation=verifyImage({sha:admitted.sha,digest:admitted.digest,runner:attestationRunner});
 return accredit(admitted,context,{...github,imageDigest:attestation.digest,attestationVerified:attestation.verified,requiredChecksPassed:checks.sha===admitted.sha});
}
