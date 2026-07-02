import { ScanRule, RuleColor, ValidatorOutput, Severity } from '../types';
import { createScopedLogger } from './logger';

const logger = createScopedLogger('Validation');
const VALID_COLORS: RuleColor[] = [
  'red',
  'orange',
  'yellow',
  'green',
  'cyan',
  'blue',
  'pink',
  'magenta',
  'gray',
  'none',
];

export const SEVERITY = {
  NONE: 'none' as Severity,
  LOW: 'low' as Severity,
  MEDIUM: 'medium' as Severity,
  HIGH: 'high' as Severity,
} as const;

const VALID_VALIDATOR_TAGS: string[] = ['none', 'low', 'medium', 'high'];

function isValidColor(value: unknown): value is RuleColor {
  return typeof value === 'string' && VALID_COLORS.includes(value as RuleColor);
}

function isValidValidatorConfig(val: unknown): boolean {
  if (typeof val !== 'object' || val === null) {
    return false;
  }
  const validator = val as Record<string, unknown>;
  if (typeof validator.command !== 'string') {
    return false;
  }
  if (validator.timeout !== undefined && typeof validator.timeout !== 'number') {
    return false;
  }
  if (validator.bulk !== undefined && (typeof validator.bulk !== 'number' || validator.bulk < 1)) {
    return false;
  }

  return true;
}

function hasValidRequiredFields(rule: Record<string, unknown>): boolean {
  return (
    typeof rule.id === 'string' &&
    rule.id.trim().length > 0 &&
    typeof rule.name === 'string' &&
    rule.name.trim().length > 0 &&
    typeof rule.group === 'string' &&
    rule.group.trim().length > 0 &&
    typeof rule.regex === 'string' &&
    rule.regex.trim().length > 0 &&
    typeof rule.loaded === 'boolean'
  );
}

export function isValidScanRule(obj: unknown): obj is ScanRule {
  if (!obj || typeof obj !== 'object') {
    return false;
  }
  const rule = obj as Record<string, unknown>;
  if (!hasValidRequiredFields(rule)) {
    return false;
  }
  if (rule.color !== undefined && !isValidColor(rule.color)) {
    return false;
  }
  if (rule.sensitive !== undefined && typeof rule.sensitive !== 'boolean') {
    return false;
  }
  if (rule.validator !== undefined && !isValidValidatorConfig(rule.validator)) {
    return false;
  }

  return true;
}

export function validateRules(raw: unknown[]): ScanRule[] {
  const validRules: ScanRule[] = [];
  let invalidCount = 0;
  for (const item of raw) {
    if (isValidScanRule(item)) {
      validRules.push({
        ...item,
        color: item.color ?? 'none',
        sensitive: item.sensitive ?? false,
      });
    } else {
      invalidCount++;
      logger.debug('Invalid rule data skipped:', item);
    }
  }
  if (invalidCount > 0) {
    logger.warn(`Skipped ${invalidCount} invalid rule(s) during validation`);
  }

  return validRules;
}

export function isValidValidatorOutput(obj: unknown): obj is ValidatorOutput {
  if (!obj || typeof obj !== 'object') {
    return false;
  }
  const output = obj as Record<string, unknown>;
  if (!Array.isArray(output.results)) {
    return false;
  }

  return output.results.every(
    (item: unknown) =>
      item !== null &&
      typeof item === 'object' &&
      typeof (item as Record<string, unknown>).index === 'number' &&
      typeof (item as Record<string, unknown>).tags === 'string' &&
      VALID_VALIDATOR_TAGS.includes((item as Record<string, unknown>).tags as string)
  );
}

export function isStringInRange(
  value: unknown,
  minLength: number,
  maxLength: number
): value is string {
  return typeof value === 'string' && value.length >= minLength && value.length <= maxLength;
}

export function isNumberInRange(value: unknown, min: number, max: number): value is number {
  return typeof value === 'number' && !isNaN(value) && value >= min && value <= max;
}

export function isValidFilePath(filePath: unknown): filePath is string {
  if (typeof filePath !== 'string' || filePath.length === 0) {
    return false;
  }

  return !filePath.includes('\0');
}

export function isValidExtensionList(value: unknown): value is string[] {
  if (!Array.isArray(value)) {
    return false;
  }

  return value.every((ext) => typeof ext === 'string' && ext.length > 0 && /^\.?[\w-]+$/.test(ext));
}
