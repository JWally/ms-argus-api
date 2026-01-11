// src/helpers/misc.test.ts
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { flattenObject, getCurrentDateInfo } from "./misc";

describe("flattenObject", () => {
  it("should return empty object for empty input", () => {
    expect(flattenObject({})).toEqual({});
  });

  it("should handle single level object", () => {
    const input = { a: 1, b: "hello", c: true };
    expect(flattenObject(input)).toEqual({ a: 1, b: "hello", c: true });
  });

  it("should flatten nested objects with dot notation", () => {
    const input = {
      user: {
        name: "John",
        age: 30,
      },
    };
    expect(flattenObject(input)).toEqual({
      "user.name": "John",
      "user.age": 30,
    });
  });

  it("should handle deeply nested objects", () => {
    const input = {
      level1: {
        level2: {
          level3: {
            value: "deep",
          },
        },
      },
    };
    expect(flattenObject(input)).toEqual({
      "level1.level2.level3.value": "deep",
    });
  });

  it("should convert arrays to JSON strings", () => {
    const input = {
      tags: ["a", "b", "c"],
      numbers: [1, 2, 3],
    };
    expect(flattenObject(input)).toEqual({
      tags: '["a","b","c"]',
      numbers: "[1,2,3]",
    });
  });

  it("should handle null values", () => {
    const input = { value: null };
    expect(flattenObject(input)).toEqual({ value: null });
  });

  it("should handle undefined values", () => {
    const input = { value: undefined };
    expect(flattenObject(input)).toEqual({ value: undefined });
  });

  it("should handle mixed nested structure", () => {
    const input = {
      name: "test",
      config: {
        enabled: true,
        settings: {
          timeout: 1000,
        },
      },
      tags: ["prod", "api"],
    };
    expect(flattenObject(input)).toEqual({
      name: "test",
      "config.enabled": true,
      "config.settings.timeout": 1000,
      tags: '["prod","api"]',
    });
  });

  it("should use custom prefix", () => {
    const input = { a: 1, b: 2 };
    expect(flattenObject(input, "prefix")).toEqual({
      "prefix.a": 1,
      "prefix.b": 2,
    });
  });

  it("should handle empty nested objects", () => {
    const input = { empty: {} };
    expect(flattenObject(input)).toEqual({});
  });
});

describe("getCurrentDateInfo", () => {
  beforeEach(() => {
    // Mock Date to return a consistent value
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("should return correct year, month, day", () => {
    vi.setSystemTime(new Date("2024-06-15T12:30:45.123Z"));
    const info = getCurrentDateInfo();

    expect(info.year).toBe(2024);
    expect(info.month).toBe(6);
    expect(info.day).toBe(15);
  });

  it("should return correct time components", () => {
    vi.setSystemTime(new Date("2024-01-01T08:30:45.123Z"));
    const info = getCurrentDateInfo();

    // Note: These will be in local timezone
    expect(typeof info.hour).toBe("number");
    expect(typeof info.minute).toBe("number");
    expect(typeof info.second).toBe("number");
    expect(info.millisecond).toBe(123);
  });

  it("should return correct day of week", () => {
    // January 1, 2024 is a Monday
    vi.setSystemTime(new Date("2024-01-01T12:00:00.000Z"));
    const info = getCurrentDateInfo();

    expect(info.day_of_week).toBe("Monday");
    expect(info.day_of_week_short).toBe("Mon");
  });

  it("should return correct month names", () => {
    vi.setSystemTime(new Date("2024-03-15T12:00:00.000Z"));
    const info = getCurrentDateInfo();

    expect(info.month_name).toBe("March");
    expect(info.month_name_short).toBe("Mar");
  });

  it("should correctly identify leap year", () => {
    vi.setSystemTime(new Date("2024-06-15T12:00:00.000Z"));
    const leapYearInfo = getCurrentDateInfo();
    expect(leapYearInfo.is_leap_year).toBe(true);

    vi.setSystemTime(new Date("2023-06-15T12:00:00.000Z"));
    const nonLeapYearInfo = getCurrentDateInfo();
    expect(nonLeapYearInfo.is_leap_year).toBe(false);
  });

  it("should return correct quarter", () => {
    vi.setSystemTime(new Date("2024-01-15T12:00:00.000Z"));
    expect(getCurrentDateInfo().quarter).toBe(1);

    vi.setSystemTime(new Date("2024-04-15T12:00:00.000Z"));
    expect(getCurrentDateInfo().quarter).toBe(2);

    vi.setSystemTime(new Date("2024-07-15T12:00:00.000Z"));
    expect(getCurrentDateInfo().quarter).toBe(3);

    vi.setSystemTime(new Date("2024-10-15T12:00:00.000Z"));
    expect(getCurrentDateInfo().quarter).toBe(4);
  });

  it("should return valid unix timestamp", () => {
    const testDate = new Date("2024-06-15T12:00:00.000Z");
    vi.setSystemTime(testDate);
    const info = getCurrentDateInfo();

    expect(info.unix_timestamp).toBe(Math.floor(testDate.getTime() / 1000));
  });

  it("should return valid ISO string", () => {
    vi.setSystemTime(new Date("2024-06-15T12:00:00.000Z"));
    const info = getCurrentDateInfo();

    expect(info.iso_string).toMatch(
      /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/,
    );
  });

  it("should calculate day of year correctly", () => {
    // January 15 = day 15
    vi.setSystemTime(new Date("2024-01-15T12:00:00.000Z"));
    const info = getCurrentDateInfo();
    expect(info.day_of_year).toBeGreaterThan(0);
    expect(info.day_of_year).toBeLessThanOrEqual(366);
  });

  it("should calculate week of year", () => {
    vi.setSystemTime(new Date("2024-01-15T12:00:00.000Z"));
    const info = getCurrentDateInfo();
    expect(info.week_of_year).toBeGreaterThan(0);
    expect(info.week_of_year).toBeLessThanOrEqual(53);
  });

  it("should return timezone information", () => {
    vi.setSystemTime(new Date("2024-06-15T12:00:00.000Z"));
    const info = getCurrentDateInfo();

    expect(typeof info.timezone).toBe("string");
    expect(info.timezone).toMatch(/^UTC[+-]\d{4}$/);
    expect(typeof info.timezone_offset).toBe("number");
    expect(typeof info.is_dst).toBe("boolean");
  });
});
