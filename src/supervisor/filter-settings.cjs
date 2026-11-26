'use strict'

// The Native Mod's (transform) and the Final Guard's (verification) detector workers must run the same detector
// filter settings: if only the Mod's filters are on, the Guard blocks text the Mod let through. Each worker reports
// its settings as on/off in its ready answer (pgdetector describe(): filter_settings); this names those that differ.
const FILTER_SETTINGS = Object.freeze(['PG_DETECTOR_FILTERS', 'PG_DETECTOR_FILTER_DUMMY'])

function setting(ready, name) {
  return ready && ready.filter_settings && ready.filter_settings[name] === 'on' ? 'on' : 'off'
}

function filterSettingsMismatch(transformReady, verificationReady) {
  return FILTER_SETTINGS.filter(name => setting(transformReady, name) !== setting(verificationReady, name))
}

// The model settings (pgdetector describe(): model_settings): the ml-span checkpoint and the verifier bundle as
// digests of their resolved paths (null when not loaded), the candidate policy, and what the model adapters do with a
// short span (PG_ML_SHORT_VALUES: strong, keep or drop; null with no model adapter). A worker that does not report
// them counts as no model and the default policy.
const MODEL_SETTINGS = Object.freeze(['PG_ML_CHECKPOINT', 'PG_VERIFIER_BUNDLE', 'PG_DETECTOR_CANDIDATE_POLICY', 'PG_ML_SHORT_VALUES'])
const MODEL_DEFAULTS = Object.freeze({ PG_ML_CHECKPOINT: null, PG_VERIFIER_BUNDLE: null, PG_DETECTOR_CANDIDATE_POLICY: 'union', PG_ML_SHORT_VALUES: null })

function modelSetting(ready, name) {
  const value = ready && ready.model_settings ? ready.model_settings[name] : undefined
  return value === undefined ? MODEL_DEFAULTS[name] : value
}

function modelSettingsMismatch(transformReady, verificationReady) {
  return MODEL_SETTINGS.filter(name => modelSetting(transformReady, name) !== modelSetting(verificationReady, name))
}

module.exports = { FILTER_SETTINGS, MODEL_SETTINGS, filterSettingsMismatch, modelSettingsMismatch }
