#!/usr/bin/env node
'use strict';
// Conformance driver for the Node implementation. See ../../protocol.md.

const fs = require('node:fs');
const path = require('node:path');

const caseFile = process.argv[2];
const testCase = JSON.parse(fs.readFileSync(caseFile, 'utf8'));
for (const [k, v] of Object.entries(testCase.env || {})) process.env[k] = v;

// eslint-disable-next-line import/no-dynamic-require
const record = require(path.join(__dirname, '..', '..', '..', 'js', 'src', 'record.cjs'));
const resourceMod = require(path.join(__dirname, '..', '..', '..', 'js', 'src', 'resource.cjs'));

const opts = testCase.input;
const rec = record.build({
  severityNumber: opts.severityNumber ?? 9,
  body: opts.body ?? '',
  eventName: opts.eventName,
  resource: resourceMod.get(),
  attributes: opts.attributes,
  traceId: opts.traceId,
  spanId: opts.spanId,
});
process.stdout.write(record.toJsonLine(rec));
