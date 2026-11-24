'use strict';

// Helpers for the tests of the action.

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

// withEnv sets the variables for one call and restores them after it. An
// undefined value removes the variable.
function withEnv(vars, fn) {
  const saved = {};
  for (const [name, value] of Object.entries(vars)) {
    saved[name] = process.env[name];
    setEnv(name, value);
  }
  try {
    return fn();
  } finally {
    for (const [name, value] of Object.entries(saved)) {
      setEnv(name, value);
    }
  }
}

function setEnv(name, value) {
  if (value === undefined) {
    delete process.env[name];
  } else {
    process.env[name] = value;
  }
}

// tempDir makes a directory that the test removes when it ends.
function tempDir(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pmg-test-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

module.exports = { tempDir, withEnv };
