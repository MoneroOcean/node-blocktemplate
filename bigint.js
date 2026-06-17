"use strict";

const BASE_DIFF = BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
const BASE_RAVEN_DIFF = BigInt("0x00000000ff000000000000000000000000000000000000000000000000000000");
const DIFF_PRECISION = 1000000000n;

function parseBigInt(value, base) {
  if (typeof value === "bigint") return value;
  if (typeof value === "number") return BigInt(Math.trunc(value));
  if (Buffer.isBuffer(value)) return BigInt(`0x${value.toString("hex") || "00"}`);
  if (typeof value === "string") {
    return BigInt(base === 16 ? `0x${value}` : value);
  }
  if (value && typeof value === "object") {
    if (typeof value.value === "bigint") return value.value;
    if (typeof value.toString === "function") {
      const stringValue = value.toString(base || 10);
      return BigInt(base === 16 ? `0x${stringValue}` : stringValue);
    }
  }
  return BigInt(value || 0);
}

function parsePositiveBigInt(value, base, label = "value") {
  let parsed;
  try {
    parsed = parseBigInt(value, base);
  } catch (_err) {
    throw new Error(`Invalid ${label}`);
  }
  if (parsed <= 0n) throw new Error(`Invalid ${label}`);
  return parsed;
}

function difficultyToFloat(base, target, targetBase, label = "target") {
  const dividend = parseBigInt(base);
  const divisor = parsePositiveBigInt(target, targetBase, label);
  return Number((dividend * DIFF_PRECISION) / divisor) / Number(DIFF_PRECISION);
}

module.exports = {
  BASE_DIFF,
  BASE_RAVEN_DIFF,
  difficultyToFloat,
  parseBigInt,
  parsePositiveBigInt
};
