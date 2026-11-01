#!/usr/bin/env node
// CI-only dynamic positive control. Never deploys, changes a host, grants
// credentials, or replaces the manually pinned operator admission gate.
import { admitCurrent } from './cka_lab_image_admission.mjs';

try {
  const receipt = admitCurrent();
  console.log('CKA_LAB_IMAGE_ADMITTED ' + JSON.stringify(receipt));
} catch {
  console.error('CKA_LAB_IMAGE_ADMISSION_BLOCKED');
  process.exitCode = 1;
}
