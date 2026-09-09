import { mkdirSync, openSync, closeSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

function prepare(path) {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const fd = openSync(path, "a", 0o600);
  closeSync(fd);
}

export function createShadowEvidenceWriter(path) {
  prepare(path);
  let tail = Promise.resolve();
  let closed = false;
  const append = (record) => {
    if (closed) return Promise.resolve();
    tail = tail.then(() => {
      writeFileSync(path, `${JSON.stringify(record)}\n`, { flag: "a", mode: 0o600 });
    }).catch(() => {});
    return tail;
  };
  return Object.freeze({
    path,
    append,
    flush: () => tail,
    async close() {
      closed = true;
      await tail;
    },
  });
}

export function createMemoryEvidenceWriter() {
  const records = [];
  return Object.freeze({
    records,
    append(record) {
      records.push(structuredClone(record));
      return Promise.resolve();
    },
    flush: () => Promise.resolve(),
    close: () => Promise.resolve(),
  });
}
