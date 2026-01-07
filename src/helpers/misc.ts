// src/helpers/misc.ts

/**
 * Flattens a nested object structure into a single-level object with dot notation keys.
 */
export type NestedValue =
  | string
  | number
  | boolean
  | null
  | undefined
  | unknown[]
  | Record<string, unknown>
  | DateTimeInfo
  | unknown;

export type NestedObject = Record<string, NestedValue>;

export const flattenObject = (
  obj: NestedObject,
  prefix: string = '',
  result: Record<string, unknown> = {},
): Record<string, unknown> => {
  for (const key in obj) {
    if (Object.prototype.hasOwnProperty.call(obj, key)) {
      const value = obj[key];
      const newKey = prefix ? `${prefix}.${key}` : key;

      if (Array.isArray(value)) {
        result[newKey] = JSON.stringify(value);
      } else if (typeof value === 'object' && value !== null) {
        flattenObject(value as NestedObject, newKey, result);
      } else {
        result[newKey] = value;
      }
    }
  }
  return result;
};

interface DateTimeInfo {
  year: number;
  month: number;
  day: number;
  hour: number;
  minute: number;
  second: number;
  millisecond: number;
  day_of_week: string;
  day_of_week_short: string;
  day_of_year: number;
  week_of_year: number;
  month_name: string;
  month_name_short: string;
  quarter: number;
  is_leap_year: boolean;
  timezone: string;
  timezone_name: string;
  timezone_offset: number;
  is_dst: boolean;
  unix_timestamp: number;
  iso_string: string;
}

export const getCurrentDateInfo = (): DateTimeInfo => {
  const now = new Date();

  const days = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
  const daysShort = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
  const months = [
    'January', 'February', 'March', 'April', 'May', 'June',
    'July', 'August', 'September', 'October', 'November', 'December',
  ];
  const monthsShort = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

  const startOfYear = new Date(now.getFullYear(), 0, 0);
  const diff = now.getTime() - startOfYear.getTime();
  const oneDay = 1000 * 60 * 60 * 24;
  const dayOfYear = Math.floor(diff / oneDay);

  const date = new Date(now.getTime());
  date.setHours(0, 0, 0, 0);
  date.setDate(date.getDate() + 3 - ((date.getDay() + 6) % 7));
  const week1 = new Date(date.getFullYear(), 0, 4);
  const weekOfYear = 1 + Math.round(((date.getTime() - week1.getTime()) / 86400000 - 3 + ((week1.getDay() + 6) % 7)) / 7);

  const isLeapYear = new Date(now.getFullYear(), 1, 29).getMonth() === 1;

  const timezoneOffset = now.getTimezoneOffset();
  const offsetHours = Math.abs(Math.floor(timezoneOffset / 60));
  const offsetMinutes = Math.abs(timezoneOffset % 60);
  const timezoneString = `UTC${timezoneOffset <= 0 ? '+' : '-'}${offsetHours.toString().padStart(2, '0')}${offsetMinutes.toString().padStart(2, '0')}`;

  const jan = new Date(now.getFullYear(), 0, 1);
  const jul = new Date(now.getFullYear(), 6, 1);
  const isDST = now.getTimezoneOffset() < Math.max(jan.getTimezoneOffset(), jul.getTimezoneOffset());

  const timeString = now.toTimeString();
  const timezoneName = timeString.substring(timeString.indexOf('(') + 1, timeString.indexOf(')'));

  const quarter = Math.floor((now.getMonth() + 3) / 3);

  return {
    year: now.getFullYear(),
    month: now.getMonth() + 1,
    day: now.getDate(),
    hour: now.getHours(),
    minute: now.getMinutes(),
    second: now.getSeconds(),
    millisecond: now.getMilliseconds(),
    day_of_week: days[now.getDay()],
    day_of_week_short: daysShort[now.getDay()],
    day_of_year: dayOfYear,
    week_of_year: weekOfYear,
    month_name: months[now.getMonth()],
    month_name_short: monthsShort[now.getMonth()],
    quarter: quarter,
    is_leap_year: isLeapYear,
    timezone: timezoneString,
    timezone_name: timezoneName,
    timezone_offset: timezoneOffset,
    is_dst: isDST,
    unix_timestamp: Math.floor(now.getTime() / 1000),
    iso_string: now.toISOString(),
  };
};
