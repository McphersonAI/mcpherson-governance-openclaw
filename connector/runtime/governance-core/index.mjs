// Packaged runtime artifact: the exact shared-core source files exported here
// are copied byte-for-byte and verified by the standalone-install test. The
// evaluator and enforcement gate are deliberately absent from this package.
export { canonicalizeJson, correlationRef, requestHash } from "./canonical.mjs";
export { ACTION_CLASSES } from "./classify.mjs";
export {
  validateAttemptReceipt,
  validateCompletionReceipt,
  validateDecision,
  validateDecisionRequest,
} from "./contracts.mjs";
