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

module.exports = { FILTER_SETTINGS, filterSettingsMismatch }
