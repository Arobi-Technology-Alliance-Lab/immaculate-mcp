import assert from 'node:assert/strict';
import test from 'node:test';

import { jsonToStruct, structToJson } from '../src/struct.mjs';

test('a Struct round-trips plain JSON: strings, numbers, booleans, null, lists and nested objects', () => {
  const value = { rules: [{ id: 'a', methods: ['GET'], n: 3.5, on: true, none: null, nested: { deep: [1, 'x', false] } }], unmatched: 'deny' };
  assert.deepEqual(structToJson(jsonToStruct(value)), value);
});

test('an absent Struct is null, and an empty one is an empty object', () => {
  assert.equal(structToJson(undefined), null);
  assert.equal(structToJson(null), null);
  assert.deepEqual(structToJson({ fields: {} }), {});
  assert.deepEqual(structToJson({}), {});
});

test('a Struct value with no kind set is refused rather than read as something', () => {
  assert.throws(() => structToJson({ fields: { a: {} } }), /no kind set/);
  assert.throws(() => structToJson({ fields: { a: null } }), /one kind set/);
});

test('only an object becomes a Struct, and only finite numbers', () => {
  assert.throws(() => jsonToStruct([1]), /Only an object/);
  assert.throws(() => jsonToStruct({ a: Number.NaN }), /finite/);
  assert.throws(() => jsonToStruct({ a: () => 1 }), /cannot hold a function/);
});

test('a Struct nested past the limit is refused', () => {
  let value = { leaf: 1 };
  for (let i = 0; i < 40; i += 1) value = { next: value };
  assert.throws(() => structToJson(jsonToStruct(value)), /nests at most/);
});
