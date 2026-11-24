'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { cloudMode, exchange, isForkPullRequest } = require('./workload');

function withEnv(vars, fn) {
  const saved = {};
  for (const [name, value] of Object.entries(vars)) {
    saved[name] = process.env[name];
    process.env[name] = value;
  }
  try {
    return fn();
  } finally {
    for (const [name, value] of Object.entries(saved)) {
      if (value === undefined) {
        delete process.env[name];
      } else {
        process.env[name] = value;
      }
    }
  }
}

test('cloudMode', async (t) => {
  for (const [name, env, want] of [
    ['tenant-id alone selects OIDC', { 'INPUT_TENANT-ID': 'acme.safedep.io', 'INPUT_API-KEY': '' }, 'oidc'],
    ['api-key takes precedence', { 'INPUT_TENANT-ID': 'acme.safedep.io', 'INPUT_API-KEY': 'sfd_key' }, 'api-key'],
    ['no input turns the cloud off', { 'INPUT_TENANT-ID': '', 'INPUT_API-KEY': '' }, ''],
  ]) {
    await t.test(name, () => assert.strictEqual(withEnv(env, cloudMode), want));
  }
});

test('isForkPullRequest', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pmg-event-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const event = (head) => {
    const file = path.join(dir, `${Math.random()}.json`);
    fs.writeFileSync(file, JSON.stringify({ pull_request: { head: { repo: head }, base: { repo: { full_name: 'acme/app' } } } }));
    return file;
  };

  for (const [name, eventName, head, want] of [
    ['a pull request from a fork', 'pull_request', { full_name: 'mallory/app' }, true],
    ['a pull request from a fork that is gone', 'pull_request', null, true],
    ['a pull request from a branch of the repository', 'pull_request', { full_name: 'acme/app' }, false],
    ['a review of a pull request from a fork', 'pull_request_review', { full_name: 'mallory/app' }, true],
    ['a review comment on a pull request from a fork', 'pull_request_review_comment', { full_name: 'mallory/app' }, true],
    ['a review of a pull request from a branch of the repository', 'pull_request_review', { full_name: 'acme/app' }, false],
    ['pull_request_target gets an ID token', 'pull_request_target', { full_name: 'mallory/app' }, false],
    ['a push', 'push', { full_name: 'mallory/app' }, false],
  ]) {
    await t.test(name, () =>
      assert.strictEqual(withEnv({ GITHUB_EVENT_NAME: eventName, GITHUB_EVENT_PATH: event(head) }, isForkPullRequest), want));
  }
});

test('exchange warns on a fork pull request before it checks the PMG release', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pmg-event-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'event.json');
  fs.writeFileSync(file, JSON.stringify({ pull_request: { head: { repo: { full_name: 'mallory/app' } }, base: { repo: { full_name: 'acme/app' } } } }));

  const env = {
    GITHUB_EVENT_NAME: 'pull_request',
    GITHUB_EVENT_PATH: file,
    ACTIONS_ID_TOKEN_REQUEST_URL: '',
    ACTIONS_ID_TOKEN_REQUEST_TOKEN: '',
    'INPUT_TENANT-ID': 'acme.safedep.io',
  };
  assert.strictEqual(withEnv(env, () => exchange(path.join(dir, 'old-pmg-release'))), null);
});
