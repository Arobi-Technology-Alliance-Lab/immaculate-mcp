/**
 * Copyright (c) 2026 Arobi Technology Alliance, Inc. All Rights Reserved.
 *
 * google.protobuf.Struct as @grpc/proto-loader decodes it, to plain JSON and back. OpenShell carries a policy entry's
 * `config` object as a Struct in ValidateConfig and in every request preflight.
 *
 * proto-loader serves google/protobuf/struct.proto from protobufjs's bundled definitions, whose Value fields are
 * camelCase (stringValue, listValue, ...) even when the rest of the protocol keeps its snake_case names. Both spellings
 * are read here, so the conversion does not depend on where the definition came from; Structs are written camelCase.
 */

const MAX_DEPTH = 32;

const KINDS = {
  nullValue: 'null',
  null_value: 'null',
  numberValue: 'number',
  number_value: 'number',
  stringValue: 'string',
  string_value: 'string',
  boolValue: 'bool',
  bool_value: 'bool',
  structValue: 'struct',
  struct_value: 'struct',
  listValue: 'list',
  list_value: 'list',
};

/** The field holding a Value's content: the decoded oneof name, or the one kind field present. */
function kindField(value) {
  if (typeof value.kind === 'string' && Object.hasOwn(KINDS, value.kind)) return value.kind;
  const present = Object.keys(value).filter((key) => Object.hasOwn(KINDS, key) && value[key] !== undefined && value[key] !== null);
  return present.length === 1 ? present[0] : null;
}

/** A decoded Struct ({ fields: { name: Value } }) as a plain object; null when the Struct is absent. */
export function structToJson(struct, depth = 0) {
  if (struct === null || struct === undefined) return null;
  if (typeof struct !== 'object') throw new TypeError('A Struct is an object.');
  if (depth > MAX_DEPTH) throw new TypeError(`A Struct nests at most ${MAX_DEPTH} levels.`);
  const out = {};
  for (const [name, value] of Object.entries(struct.fields || {})) {
    out[name] = valueToJson(value, depth + 1);
  }
  return out;
}

function valueToJson(value, depth) {
  if (value === null || value === undefined || typeof value !== 'object') {
    throw new TypeError('A Struct value is an object with one kind set.');
  }
  const field = kindField(value);
  switch (field ? KINDS[field] : null) {
    case 'null':
      return null;
    case 'number':
      return Number(value[field]);
    case 'string':
      return String(value[field]);
    case 'bool':
      return Boolean(value[field]);
    case 'struct':
      return structToJson(value[field] || { fields: {} }, depth);
    case 'list':
      if (depth > MAX_DEPTH) throw new TypeError(`A Struct nests at most ${MAX_DEPTH} levels.`);
      return (value[field]?.values || []).map((item) => valueToJson(item, depth + 1));
    default:
      throw new TypeError('A Struct value has no kind set.');
  }
}

/** A plain object as a Struct message for @grpc/proto-loader to encode. */
export function jsonToStruct(object) {
  if (object === null || typeof object !== 'object' || Array.isArray(object)) {
    throw new TypeError('Only an object becomes a Struct.');
  }
  return { fields: Object.fromEntries(Object.entries(object).map(([name, value]) => [name, jsonToValue(value)])) };
}

function jsonToValue(value) {
  if (value === null) return { nullValue: 'NULL_VALUE' };
  if (Array.isArray(value)) return { listValue: { values: value.map(jsonToValue) } };
  switch (typeof value) {
    case 'number':
      if (!Number.isFinite(value)) throw new TypeError('A Struct number is finite.');
      return { numberValue: value };
    case 'string':
      return { stringValue: value };
    case 'boolean':
      return { boolValue: value };
    case 'object':
      return { structValue: jsonToStruct(value) };
    default:
      throw new TypeError(`A Struct cannot hold a ${typeof value}.`);
  }
}
