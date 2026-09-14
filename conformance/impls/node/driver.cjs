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
const caller = require(path.join(__dirname, '..', '..', '..', 'js', 'src', 'caller.cjs'));

const opts = testCase.input;

// Mirrors what capture.cjs's emitRecord() does before calling record.build()
// — the driver itself is a manual "entry point", same as a real app's.
const attributes = caller.enabled() ? caller.callerAttributes() : {};
Object.assign(attributes, opts.attributes);

const rec = record.build({
  severityNumber: opts.severityNumber ?? 9,
  body: opts.body ?? '',
  eventName: opts.eventName,
  resource: resourceMod.get(),
  attributes,
  traceId: opts.traceId,
  spanId: opts.spanId,
});
process.stdout.write(record.toJsonLine(rec));
