import { test } from "node:test";
import assert from "node:assert/strict";
import { bucketToDeleteForHour } from "../cleanupJob";

// Matches requirement PDF p.14's schedule table exactly.
test("bucket-to-delete matches the spec's schedule table", () => {
  assert.equal(bucketToDeleteForHour(0), 23);
  assert.equal(bucketToDeleteForHour(1), 0);
  assert.equal(bucketToDeleteForHour(2), 1);
  assert.equal(bucketToDeleteForHour(3), 2);
  assert.equal(bucketToDeleteForHour(23), 22);
});

test("bucket-to-delete stays within 0-23 for every hour of the day", () => {
  for (let hour = 0; hour < 24; hour++) {
    const bucket = bucketToDeleteForHour(hour);
    assert.ok(bucket >= 0 && bucket <= 23, `bucket ${bucket} out of range for hour ${hour}`);
  }
});
