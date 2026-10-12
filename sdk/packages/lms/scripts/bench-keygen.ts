/** Times key generation per height. Run from sdk/: node packages/lms/scripts/bench-keygen.ts */
import { LMS_SHA256_M32_H10, LMS_SHA256_M32_H15, LMS_SHA256_M32_H5, LmsPrivateKey, randomKeyMaterial } from "../src/index.ts";

const heights = process.argv.includes("--h15")
  ? [LMS_SHA256_M32_H5, LMS_SHA256_M32_H10, LMS_SHA256_M32_H15]
  : [LMS_SHA256_M32_H5, LMS_SHA256_M32_H10];

for (const t of heights) {
  const mat = randomKeyMaterial(t);
  const t0 = performance.now();
  const key = LmsPrivateKey.generate(mat);
  const ms = performance.now() - t0;
  console.log(`${key.lms.name}: ${key.leafCount} leaves in ${ms.toFixed(0)} ms (${((ms * 1000) / key.leafCount).toFixed(0)} us/leaf)`);
}
