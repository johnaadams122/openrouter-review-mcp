import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { isAbsolute, join, relative, resolve, sep } from 'node:path';
import { resolveReviewSourcePath } from '../source-contract.mjs';
import { validateExtraProtectedTerms } from '../scrub-patterns.mjs';
import { SHARED_LIMITS, canonicalJson, sharedError } from './contracts.mjs';

const DIGEST = /^[a-f0-9]{64}$/;
const OPAQUE_ID = /^[A-Za-z0-9_-]{1,128}$/;
const MAX_FREE_TIER_PROJECT_IDS = 1_024;

function invalidConfig() {
  return sharedError('INVALID_INSTALLATION_CONFIG');
}

function fail(message = 'invalid value') {
  throw new TypeError(message);
}

function strictObject(value, required, optional = [], field = 'value') {
  if (value === null || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) fail(`${field} must be a plain object`);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  for (const key of Reflect.ownKeys(descriptors)) {
    if (typeof key !== 'string') fail(`${field} cannot contain symbols`);
    const descriptor = descriptors[key];
    if (!descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) fail(`${field}.${key} must be an enumerable data property`);
  }
  const keys = Object.keys(descriptors);
  const allowed = new Set([...required, ...optional]);
  if (keys.some((key) => !allowed.has(key)) || required.some((key) => !Object.hasOwn(descriptors, key))) fail(`${field} has an invalid shape`);
  return Object.fromEntries(keys.map((key) => [key, descriptors[key].value]));
}

function strictArray(value, field, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) fail(`${field} must be an array`);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(descriptors).some((key) => typeof key !== 'string')) fail(`${field} cannot contain symbols`);
  if (!descriptors.length || descriptors.length.enumerable || !Object.hasOwn(descriptors.length, 'value')) fail(`${field} has an invalid length`);
  if (value.length < min || value.length > max) fail(`${field} length is out of range`);
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = descriptors[String(index)];
    if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) fail(`${field} must be dense`);
  }
  const extras = Object.keys(descriptors).filter((key) => key !== 'length' && (!/^(0|[1-9][0-9]*)$/.test(key) || Number(key) >= value.length));
  if (extras.length > 0) fail(`${field} cannot have extra properties`);
  return Array.from({ length: value.length }, (_, index) => descriptors[String(index)].value);
}

function strictClone(value) {
  return JSON.parse(canonicalJson(value));
}

function deepFreeze(value) {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const nested of Object.values(value)) deepFreeze(nested);
    Object.freeze(value);
  }
  return value;
}

function opaque(value, field) {
  if (typeof value !== 'string' || !OPAQUE_ID.test(value)) fail(`${field} must be an opaque ID`);
  return value;
}

function nonempty(value, field) {
  if (typeof value !== 'string' || value.length === 0) fail(`${field} must be non-empty`);
  return value;
}

function digest(value, field) {
  if (typeof value !== 'string' || !DIGEST.test(value)) fail(`${field} must be a digest`);
  return value;
}

function positive(value, field, maximum = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value <= 0 || value > maximum) fail(`${field} must be a bounded positive safe integer`);
  return value;
}

function nonnegative(value, field) {
  if (!Number.isSafeInteger(value) || value < 0) fail(`${field} must be a non-negative safe integer`);
  return value;
}

function usd(value, field) {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) fail(`${field} must be finite non-negative USD`);
  return value;
}

function absolutePath(value, field) {
  if (typeof value !== 'string' || !isAbsolute(value) || resolve(value) !== value) fail(`${field} must be a normalized absolute path`);
  return value;
}

function normalizedForComparison(path) {
  return resolve(path).toLowerCase();
}

function isInside(candidate, root) {
  const rel = relative(normalizedForComparison(root), normalizedForComparison(candidate));
  return rel === '' || (rel !== '..' && !rel.startsWith(`..${sep}`) && !isAbsolute(rel));
}

function pathsOverlap(left, right) {
  return isInside(left, right) || isInside(right, left);
}

function validateReviewerIds(value, field) {
  const reviewerIds = strictArray(value, field, { min: 1, max: SHARED_LIMITS.maxReviewers });
  reviewerIds.forEach((id, index) => opaque(id, `${field}[${index}]`));
  if (new Set(reviewerIds).size !== reviewerIds.length) fail(`${field} contains a duplicate reviewer ID`);
  return reviewerIds;
}

function validateAllowedReviewerSets(value, field) {
  const values = strictArray(value, field, { min: 1 });
  const seen = new Set();
  let largestReviewerCount = 0;
  const sets = values.map((candidate, index) => {
    const reviewerIds = validateReviewerIds(candidate, `${field}[${index}]`);
    const identity = canonicalJson(reviewerIds);
    if (seen.has(identity)) fail(`${field} contains a duplicate reviewer set`);
    seen.add(identity);
    largestReviewerCount = Math.max(largestReviewerCount, reviewerIds.length);
    return reviewerIds;
  });
  return { sets, largestReviewerCount };
}

function validateProfile(value, field = 'profile') {
  const profile = strictObject(value, ['profileId', 'profileVersion', 'allowedReviewerSets'], [], field);
  opaque(profile.profileId, `${field}.profileId`);
  opaque(profile.profileVersion, `${field}.profileVersion`);
  const reviewerSets = validateAllowedReviewerSets(profile.allowedReviewerSets, `${field}.allowedReviewerSets`);
  return { profile, ...reviewerSets };
}

export function isAllowedReviewerSet(profile, reviewerIds) {
  try {
    const { sets } = validateProfile(profile);
    const candidate = validateReviewerIds(reviewerIds, 'reviewerIds');
    return sets.some((allowed) => allowed.length === candidate.length
      && allowed.every((reviewerId, index) => reviewerId === candidate[index]));
  } catch {
    return false;
  }
}

export function largestAllowedReviewerCount(profile) {
  try {
    return validateProfile(profile).largestReviewerCount;
  } catch {
    throw invalidConfig();
  }
}

function validateProfiles(value) {
  const profiles = strictArray(value, 'review.allowedProfiles', { min: 1 });
  const profileIds = new Set();
  let maxReviewerCount = 0;
  profiles.forEach((item, index) => {
    const { profile, largestReviewerCount } = validateProfile(item, `allowedProfiles[${index}]`);
    if (profileIds.has(profile.profileId)) fail('duplicate profile ID');
    profileIds.add(profile.profileId);
    maxReviewerCount = Math.max(maxReviewerCount, largestReviewerCount);
  });
  return maxReviewerCount;
}

// The free-tier list is installation configuration: which project IDs may ever be marked
// free-eligible. It is required (an empty list is the public default and admits none), so an
// installation cannot quietly differ from what its owner stated.
function validateFreeTierProjectIds(value) {
  const ids = strictArray(value, 'freeTierProjectIds', { max: MAX_FREE_TIER_PROJECT_IDS });
  ids.forEach((id, index) => opaque(id, `freeTierProjectIds[${index}]`));
  if (new Set(ids).size !== ids.length) fail('freeTierProjectIds contains a duplicate');
  return new Set(ids);
}

// Owner-supplied extra protected terms, as the installer sealed them: sourceSha256 is the SHA-256
// of the owner's terms file (null only for the explicit "none"), and the two lists are exactly what
// that file parsed to. A named source must contribute at least one term; "none" must contribute none.
function validateExtraProtectedTermsSetting(value) {
  const setting = strictObject(value, ['sourceSha256', 'markers', 'contextTerms'], [], 'engine.extraProtectedTerms');
  const terms = validateExtraProtectedTerms({ markers: setting.markers, contextTerms: setting.contextTerms });
  const termCount = terms.markers.length + terms.contextTerms.length;
  if (setting.sourceSha256 === null) {
    if (termCount !== 0) fail('engine.extraProtectedTerms without a source must be empty');
  } else {
    digest(setting.sourceSha256, 'engine.extraProtectedTerms.sourceSha256');
    if (termCount === 0) fail('engine.extraProtectedTerms with a source must list at least one term');
  }
}

function validateConfigInner(value) {
  canonicalJson(value);
  const config = strictObject(value, ['version', 'protocolVersion', 'storageVersion', 'dataRoot', 'buildManifestSha256', 'engine', 'review', 'queue', 'storage', 'transport', 'freeTierProjectIds', 'projects', 'bindings', 'protectedReferences'], [], 'config');
  if (config.version !== 'shared-review-installation-v1' || config.protocolVersion !== 'shared-review-pipe-v1' || config.storageVersion !== 'shared-review-storage-v1') fail('invalid config version');
  absolutePath(config.dataRoot, 'dataRoot');
  digest(config.buildManifestSha256, 'buildManifestSha256');

  const engine = strictObject(config.engine, ['installationHardMaximumUsd', 'dailyPaidJobAllowance', 'autonomousAuthorization', 'maxSourceBytes', 'maxRequestBytes', 'dispatchTimeoutMs', 'preflightTtlMs', 'orphanSweepGraceMs', 'healthVerdictGraceMs', 'healthVerdictBackstopMs', 'armTimeoutMs', 'armLockRetryMs', 'shutdownDrainTimeoutMs', 'ollamaBaseUrl', 'ollamaModel', 'ollamaTimeoutMs', 'identityListDigest', 'classifierContractDigest', 'extraProtectedTerms', 'spendAlertThresholdFraction', 'consecutiveDispatchFailureAlertThreshold', 'keyStatusProbeTimeoutMs', 'approvalAdapterVersion', 'dispatchAdapterVersion', 'healthAdapterVersion', 'alertAdapterVersion', 'alertAdapterReference'], [], 'engine');
  usd(engine.installationHardMaximumUsd, 'engine.installationHardMaximumUsd');
  positive(engine.dailyPaidJobAllowance, 'engine.dailyPaidJobAllowance');
  if (typeof engine.autonomousAuthorization !== 'boolean') fail('engine.autonomousAuthorization must be boolean');
  positive(engine.maxSourceBytes, 'engine.maxSourceBytes', SHARED_LIMITS.maxSourceBytes);
  positive(engine.maxRequestBytes, 'engine.maxRequestBytes', SHARED_LIMITS.maxRequestBytes);
  for (const name of ['dispatchTimeoutMs', 'preflightTtlMs', 'orphanSweepGraceMs', 'healthVerdictGraceMs', 'healthVerdictBackstopMs', 'armTimeoutMs', 'armLockRetryMs', 'shutdownDrainTimeoutMs', 'ollamaTimeoutMs']) positive(engine[name], `engine.${name}`);
  nonempty(engine.ollamaBaseUrl, 'engine.ollamaBaseUrl');
  nonempty(engine.ollamaModel, 'engine.ollamaModel');
  digest(engine.identityListDigest, 'engine.identityListDigest');
  digest(engine.classifierContractDigest, 'engine.classifierContractDigest');
  validateExtraProtectedTermsSetting(engine.extraProtectedTerms);
  if (typeof engine.spendAlertThresholdFraction !== 'number' || !Number.isFinite(engine.spendAlertThresholdFraction) || engine.spendAlertThresholdFraction <= 0 || engine.spendAlertThresholdFraction > 1) fail('invalid alert fraction');
  positive(engine.consecutiveDispatchFailureAlertThreshold, 'engine.consecutiveDispatchFailureAlertThreshold', 9_999);
  if (engine.keyStatusProbeTimeoutMs !== 20_000) fail('invalid key-status timeout');
  if (engine.approvalAdapterVersion !== 'local-human-approval-v1' || engine.dispatchAdapterVersion !== 'shared-review-dispatch-v1' || engine.healthAdapterVersion !== 'local-dispatch-health-v1' || engine.alertAdapterVersion !== 'local-alert-store-v1') fail('invalid adapter version');
  opaque(engine.alertAdapterReference, 'engine.alertAdapterReference');

  const review = strictObject(config.review, ['registrySha256', 'advisorySchemaSha256', 'promptVersion', 'profileCatalogDigest', 'allowedProfiles'], [], 'review');
  digest(review.registrySha256, 'review.registrySha256');
  digest(review.advisorySchemaSha256, 'review.advisorySchemaSha256');
  opaque(review.promptVersion, 'review.promptVersion');
  digest(review.profileCatalogDigest, 'review.profileCatalogDigest');
  const maxProfileReviewers = validateProfiles(review.allowedProfiles);

  const queue = strictObject(config.queue, ['maxActiveBatches', 'maxWaitingCallerRequests', 'maxUnfinishedCount', 'maxActiveReviewerDispatches', 'maxUnfinishedEncryptedBytes', 'maxUnstartedWaitMs', 'maxReceiptMetadataBytes', 'maxIdempotencyKeysPerLease'], [], 'queue');
  positive(queue.maxActiveBatches, 'queue.maxActiveBatches', SHARED_LIMITS.maxActiveBatches);
  positive(queue.maxWaitingCallerRequests, 'queue.maxWaitingCallerRequests', SHARED_LIMITS.maxWaitingCallerRequests);
  positive(queue.maxUnfinishedCount, 'queue.maxUnfinishedCount', SHARED_LIMITS.maxUnfinishedCount);
  positive(queue.maxActiveReviewerDispatches, 'queue.maxActiveReviewerDispatches', SHARED_LIMITS.maxActiveReviewerDispatches);
  positive(queue.maxUnfinishedEncryptedBytes, 'queue.maxUnfinishedEncryptedBytes', SHARED_LIMITS.maxUnfinishedEncryptedBytes);
  positive(queue.maxUnstartedWaitMs, 'queue.maxUnstartedWaitMs', SHARED_LIMITS.maxUnstartedWaitMs);
  positive(queue.maxReceiptMetadataBytes, 'queue.maxReceiptMetadataBytes', SHARED_LIMITS.maxReceiptMetadataBytes);
  positive(queue.maxIdempotencyKeysPerLease, 'queue.maxIdempotencyKeysPerLease', SHARED_LIMITS.maxIdempotencyKeysPerLease);
  if (queue.maxUnfinishedCount !== queue.maxActiveBatches + queue.maxWaitingCallerRequests
    || queue.maxActiveReviewerDispatches < queue.maxActiveBatches
    || queue.maxActiveReviewerDispatches < maxProfileReviewers
    || queue.maxUnfinishedEncryptedBytes < maximumPreparedEncryptedBytes({ reviewerCount: maxProfileReviewers, maxRequestBytes: engine.maxRequestBytes })) fail('inconsistent queue limits');

  const storage = strictObject(config.storage, ['maxLivePreflights', 'maxPreflightEncryptedBytes', 'maxSinglePreflightPlaintextBytes'], [], 'storage');
  positive(storage.maxLivePreflights, 'storage.maxLivePreflights', SHARED_LIMITS.maxLivePreflights);
  positive(storage.maxPreflightEncryptedBytes, 'storage.maxPreflightEncryptedBytes', SHARED_LIMITS.maxPreflightEncryptedBytes);
  positive(storage.maxSinglePreflightPlaintextBytes, 'storage.maxSinglePreflightPlaintextBytes', SHARED_LIMITS.maxSinglePreflightPlaintextBytes);
  if (maximumPreflightEncryptedBytes({ maxSinglePreflightPlaintextBytes: storage.maxSinglePreflightPlaintextBytes }) > storage.maxPreflightEncryptedBytes) fail('preflight reservation exceeds global cap');

  const transport = strictObject(config.transport, ['helloBytes', 'controlFrameBytes', 'metadataFrameBytes', 'contentFrameBytes', 'chunkRawBytes', 'maxEncodedRequestBytes', 'maxConnections', 'maxInflightIngressBytes', 'maxResultTransfers', 'maxResultBufferBytes', 'authenticationTimeoutMs'], [], 'transport');
  const transportMaxima = { helloBytes: SHARED_LIMITS.helloBytes, controlFrameBytes: SHARED_LIMITS.controlFrameBytes, metadataFrameBytes: SHARED_LIMITS.metadataFrameBytes, contentFrameBytes: SHARED_LIMITS.contentFrameBytes, chunkRawBytes: SHARED_LIMITS.chunkRawBytes, maxEncodedRequestBytes: SHARED_LIMITS.maxEncodedRequestBytes, maxConnections: SHARED_LIMITS.maxConnections, maxInflightIngressBytes: SHARED_LIMITS.maxInflightIngressBytes, maxResultTransfers: SHARED_LIMITS.maxResultTransfers, maxResultBufferBytes: SHARED_LIMITS.maxResultBufferBytes, authenticationTimeoutMs: SHARED_LIMITS.authenticationTimeoutMs };
  for (const [name, maximum] of Object.entries(transportMaxima)) positive(transport[name], `transport.${name}`, maximum);
  if ((4 * Math.ceil(transport.chunkRawBytes / 3)) + transport.metadataFrameBytes > transport.contentFrameBytes || transport.maxInflightIngressBytes < transport.maxEncodedRequestBytes) fail('inconsistent transport limits');

  const freeTierProjects = validateFreeTierProjectIds(config.freeTierProjectIds);
  const projects = strictArray(config.projects, 'projects', { min: 1 });
  const projectById = new Map();
  const projectRoots = [];
  projects.forEach((item, index) => {
    const project = strictObject(item, ['projectId', 'policyEpoch', 'canonicalRoots', 'freeEligible'], [], `projects[${index}]`);
    opaque(project.projectId, `projects[${index}].projectId`);
    positive(project.policyEpoch, `projects[${index}].policyEpoch`);
    if (typeof project.freeEligible !== 'boolean' || (project.freeEligible && !freeTierProjects.has(project.projectId))) fail('invalid free eligibility');
    if (projectById.has(project.projectId)) fail('duplicate project ID');
    const roots = strictArray(project.canonicalRoots, `projects[${index}].canonicalRoots`);
    roots.forEach((root, rootIndex) => absolutePath(root, `projects[${index}].canonicalRoots[${rootIndex}]`));
    if (new Set(roots.map(normalizedForComparison)).size !== roots.length) fail('duplicate project root');
    for (const root of roots) {
      for (const prior of projectRoots) if (prior.projectId !== project.projectId && pathsOverlap(root, prior.root)) fail('ambiguous project roots');
      projectRoots.push({ projectId: project.projectId, root });
    }
    projectById.set(project.projectId, project);
  });

  const bindings = strictArray(config.bindings, 'bindings', { min: 1 });
  const bindingIds = new Set();
  bindings.forEach((item, index) => {
    const binding = strictObject(item, ['bindingId', 'enabled', 'credentialVersion', 'credentialDigest', 'legacyRecovery', 'domains', 'defaultInlineProjectId'], [], `bindings[${index}]`);
    opaque(binding.bindingId, `bindings[${index}].bindingId`);
    if (bindingIds.has(binding.bindingId)) fail('duplicate binding ID');
    bindingIds.add(binding.bindingId);
    if (typeof binding.enabled !== 'boolean' || typeof binding.legacyRecovery !== 'boolean') fail('binding flags must be boolean');
    opaque(binding.credentialVersion, 'binding.credentialVersion');
    digest(binding.credentialDigest, 'binding.credentialDigest');
    const domains = strictArray(binding.domains, `bindings[${index}].domains`, { min: 1 });
    const domainIds = new Set();
    domains.forEach((domainValue, domainIndex) => {
      const domain = strictObject(domainValue, ['projectId', 'allowedRoots', 'freeEligible'], [], `domains[${domainIndex}]`);
      opaque(domain.projectId, 'domain.projectId');
      const project = projectById.get(domain.projectId);
      if (!project || domainIds.has(domain.projectId)) fail('invalid binding domain');
      domainIds.add(domain.projectId);
      if (typeof domain.freeEligible !== 'boolean' || (domain.freeEligible && !project.freeEligible)) fail('binding widens free eligibility');
      const roots = strictArray(domain.allowedRoots, `domains[${domainIndex}].allowedRoots`);
      roots.forEach((root, rootIndex) => {
        absolutePath(root, `domains[${domainIndex}].allowedRoots[${rootIndex}]`);
        if (!project.canonicalRoots.some((projectRoot) => isInside(root, projectRoot))) fail('binding root is outside project roots');
      });
      if (new Set(roots.map(normalizedForComparison)).size !== roots.length) fail('duplicate domain root');
    });
    if (binding.defaultInlineProjectId !== null && (typeof binding.defaultInlineProjectId !== 'string' || !domainIds.has(binding.defaultInlineProjectId))) fail('invalid inline default');
    if (domains.some((domain) => domain.allowedRoots.length === 0 && domain.projectId !== binding.defaultInlineProjectId)) fail('empty roots require an explicit inline default');
  });

  const refs = strictObject(config.protectedReferences, ['identityKeyVersion', 'identityKeyReference', 'identityListReference', 'installationCredentialReference', 'bindingCredentialStoreReference'], [], 'protectedReferences');
  for (const [name, value] of Object.entries(refs)) opaque(value, `protectedReferences.${name}`);
  return deepFreeze(strictClone(value));
}

export function validateInstallationConfig(value) {
  try { return validateConfigInner(value); } catch { throw invalidConfig(); }
}

function validateManifest(value) {
  canonicalJson(value);
  const manifest = strictObject(value, ['version', 'protocolVersion', 'storageVersion', 'node', 'files'], [], 'manifest');
  if (manifest.version !== 'shared-review-build-v1' || manifest.protocolVersion !== 'shared-review-pipe-v1' || manifest.storageVersion !== 'shared-review-storage-v1') fail('invalid manifest version');
  const node = strictObject(manifest.node, ['version', 'sha256'], [], 'manifest.node');
  nonempty(node.version, 'manifest.node.version');
  digest(node.sha256, 'manifest.node.sha256');
  const files = strictArray(manifest.files, 'manifest.files', { min: 1 });
  let prior = null;
  const folded = new Set();
  files.forEach((item, index) => {
    const file = strictObject(item, ['path', 'sha256', 'bytes'], [], `manifest.files[${index}]`);
    if (typeof file.path !== 'string' || file.path.length === 0 || file.path.includes('\\') || file.path.includes(':') || file.path.includes('\0') || file.path.startsWith('/') || file.path.split('/').some((part) => part === '' || part === '.' || part === '..')) fail('invalid manifest path');
    if (prior !== null && file.path <= prior) fail('manifest files must be sorted');
    prior = file.path;
    const lower = file.path.toLowerCase();
    if (folded.has(lower)) fail('duplicate manifest path');
    folded.add(lower);
    digest(file.sha256, 'manifest file digest');
    nonnegative(file.bytes, 'manifest file bytes');
  });
  return strictClone(value);
}

export function configurationFingerprint(config, buildManifest) {
  try {
    const validatedConfig = validateConfigInner(config);
    const manifest = validateManifest(buildManifest);
    const manifestDigest = createHash('sha256').update(canonicalJson(manifest), 'utf8').digest('hex');
    if (manifestDigest !== validatedConfig.buildManifestSha256) fail('manifest digest mismatch');
    const fingerprintConfig = strictClone(validatedConfig);
    fingerprintConfig.bindings = fingerprintConfig.bindings.map(({ credentialDigest: _credentialDigest, ...binding }) => binding);
    return createHash('sha256').update(canonicalJson({ domain: 'shared-review-configuration-v1', config: fingerprintConfig, buildManifest: manifest }), 'utf8').digest('hex');
  } catch {
    throw invalidConfig();
  }
}

function strictArguments(value, required, optional, errorCode) {
  try { return strictObject(value, required, optional, 'arguments'); } catch { throw sharedError(errorCode); }
}

function sameDigest(left, right) {
  if (typeof left !== 'string' || typeof right !== 'string' || !DIGEST.test(left) || !DIGEST.test(right)) return false;
  return timingSafeEqual(Buffer.from(left, 'hex'), Buffer.from(right, 'hex'));
}

function authenticateBinding(config, bindingId, credentialDigest, errorCode) {
  const binding = config.bindings.find((candidate) => candidate.bindingId === bindingId);
  if (!binding || !binding.enabled || !sameDigest(binding.credentialDigest, credentialDigest)) throw sharedError(errorCode);
  return binding;
}

function callerPolicy(config, binding, domain, identityDigest) {
  if (typeof identityDigest !== 'function') throw sharedError('PROJECT_SCOPE_DENIED');
  const project = config.projects.find((candidate) => candidate.projectId === domain.projectId);
  if (!project) throw sharedError('PROJECT_SCOPE_DENIED');
  let scopeDigest;
  try {
    scopeDigest = identityDigest('shared-policy-v1', Buffer.from(canonicalJson({ projectId: project.projectId, policyEpoch: project.policyEpoch, allowedRoots: domain.allowedRoots, freeEligible: domain.freeEligible }), 'utf8'));
    digest(scopeDigest, 'scopeDigest');
  } catch {
    throw sharedError('PROJECT_SCOPE_DENIED');
  }
  return deepFreeze({ bindingId: binding.bindingId, policyEpoch: project.policyEpoch, scopeDigest, projectId: project.projectId, allowedRoots: [...domain.allowedRoots], freeEligible: domain.freeEligible, defaultInlineProjectId: binding.defaultInlineProjectId, legacyRecovery: binding.legacyRecovery });
}

export async function resolveCallerPolicy(argumentsValue) {
  const args = strictArguments(argumentsValue, ['config', 'bindingId', 'credentialDigest', 'sourceKind', 'identityDigest'], ['sourcePath'], 'PROJECT_SCOPE_DENIED');
  const config = validateInstallationConfig(args.config);
  const binding = authenticateBinding(config, args.bindingId, args.credentialDigest, 'PROJECT_SCOPE_DENIED');
  if (args.sourceKind === 'inline') {
    if (args.sourcePath !== undefined) throw sharedError('PROJECT_SCOPE_DENIED');
    if (binding.defaultInlineProjectId === null) throw sharedError('PROJECT_SCOPE_REQUIRED');
    const domain = binding.domains.find((candidate) => candidate.projectId === binding.defaultInlineProjectId);
    if (!domain) throw sharedError('PROJECT_SCOPE_DENIED');
    return callerPolicy(config, binding, domain, args.identityDigest);
  }
  if (args.sourceKind !== 'path' || typeof args.sourcePath !== 'string') throw sharedError('PROJECT_SCOPE_DENIED');
  for (const domain of binding.domains) {
    if (domain.allowedRoots.length === 0) continue;
    try {
      await resolveReviewSourcePath({ sourcePath: args.sourcePath, allowedRoots: domain.allowedRoots, maxSourceBytes: config.engine.maxSourceBytes });
      return callerPolicy(config, binding, domain, args.identityDigest);
    } catch (error) {
      if (error instanceof RangeError) throw sharedError('REQUEST_TOO_LARGE');
      // Try the next non-overlapping configured domain; no rejected path detail crosses this boundary.
    }
  }
  throw sharedError('PROJECT_SCOPE_DENIED');
}

export async function resolveBoundProjectPolicy(argumentsValue) {
  const args = strictArguments(argumentsValue, ['config', 'bindingId', 'credentialDigest', 'storedProjectId', 'identityDigest'], [], 'REQUEST_NOT_FOUND');
  let config;
  try { config = validateInstallationConfig(args.config); } catch { throw sharedError('REQUEST_NOT_FOUND'); }
  const binding = authenticateBinding(config, args.bindingId, args.credentialDigest, 'REQUEST_NOT_FOUND');
  const domain = binding.domains.find((candidate) => candidate.projectId === args.storedProjectId);
  if (!domain) throw sharedError('REQUEST_NOT_FOUND');
  try { return callerPolicy(config, binding, domain, args.identityDigest); } catch { throw sharedError('REQUEST_NOT_FOUND'); }
}

export function deriveManagedInstallationRoots(canonicalDataRoot) {
  try {
    absolutePath(canonicalDataRoot, 'canonicalDataRoot');
    const managedRoot = join(canonicalDataRoot, 'managed-shared-v1');
    return Object.freeze({ managedRoot, objects: join(managedRoot, 'objects'), config: join(managedRoot, 'config'), credentials: join(managedRoot, 'credentials'), builds: join(managedRoot, 'builds') });
  } catch {
    throw invalidConfig();
  }
}

export function createAuthenticationProof(secret, domain, canonicalFields) {
  if (!Buffer.isBuffer(secret) || secret.byteLength !== 32) throw new TypeError('authentication secret must be a 32-byte Buffer');
  if (!['shared-server-proof-v1', 'shared-binding-proof-v1'].includes(domain)) throw new TypeError('unknown authentication proof domain');
  const fields = strictObject(canonicalFields, ['pipeIdentity', 'instanceId', 'nonceC', 'nonceS', 'protocolVersion', 'configFingerprint', 'buildManifestSha256', 'bindingId', 'credentialVersion'], [], 'authentication transcript');
  for (const name of ['pipeIdentity', 'instanceId', 'protocolVersion', 'bindingId', 'credentialVersion']) opaque(fields[name], name);
  for (const name of ['nonceC', 'nonceS', 'configFingerprint', 'buildManifestSha256']) digest(fields[name], name);
  const hmac = createHmac('sha256', secret);
  hmac.update(domain, 'utf8');
  hmac.update(Buffer.from([0]));
  hmac.update(canonicalJson(canonicalFields), 'utf8');
  return hmac.digest('hex');
}

export function verifyAuthenticationProof(secret, domain, fields, proof) {
  if (typeof proof !== 'string' || !DIGEST.test(proof)) return false;
  let expected;
  let received;
  try {
    expected = Buffer.from(createAuthenticationProof(secret, domain, fields), 'hex');
    received = Buffer.from(proof, 'hex');
    return timingSafeEqual(expected, received);
  } catch {
    return false;
  } finally {
    expected?.fill(0);
    received?.fill(0);
  }
}

export function maximumPreparedEncryptedBytes(value = {}) {
  const { reviewerCount, maxRequestBytes } = strictObject(value, ['reviewerCount', 'maxRequestBytes'], [], 'prepared capacity');
  positive(reviewerCount, 'reviewerCount', SHARED_LIMITS.maxReviewers);
  positive(maxRequestBytes, 'maxRequestBytes');
  // Every body and the separate 128 KiB metadata envelope are encrypted objects.
  const result = (2 * reviewerCount * maxRequestBytes) + ((reviewerCount + 3) * 131_072);
  if (!Number.isSafeInteger(result)) throw new RangeError('prepared encrypted-byte bound overflows');
  return result;
}

export function maximumPreflightEncryptedBytes(value = {}) {
  const { maxSinglePreflightPlaintextBytes } = strictObject(value, ['maxSinglePreflightPlaintextBytes'], [], 'preflight capacity');
  positive(maxSinglePreflightPlaintextBytes, 'maxSinglePreflightPlaintextBytes');
  // The joint plaintext limit covers two independently encrypted objects.
  const result = (2 * maxSinglePreflightPlaintextBytes) + (2 * 131_072);
  if (!Number.isSafeInteger(result)) throw new RangeError('preflight encrypted-byte bound overflows');
  return result;
}
