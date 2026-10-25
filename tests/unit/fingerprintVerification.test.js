import { describe, expect, jest, test } from '@jest/globals';
import { assertObservedFingerprint, expectedFingerprintSignals, verifyAppliedContextFingerprint } from '../../lib/fingerprint-verification.js';
import { createInitializedContext } from '../../lib/session-context.js';

const identity = {
  userAgent: 'Firefox/152', appVersion: '5.0', platform: 'Linux x86_64', oscpu: 'Linux x86_64',
  hardwareConcurrency: 8, screen: { width: 1600, height: 900, colorDepth: 24, deviceScaleFactor: 1 },
  locale: 'en-US', timezone: 'Asia/Shanghai',
};
const signals = () => {
  const expected = expectedFingerprintSignals(identity);
  return { ...expected, worker: { ...expected }, screenCss: [true, true] };
};

function fixture(actual = signals()) {
  const page = { on: jest.fn(), goto: jest.fn(), evaluate: jest.fn(async () => actual), close: jest.fn() };
  const context = { newPage: jest.fn(async () => page), close: jest.fn() };
  return { page, context };
}

describe('native fingerprint observable verification', () => {
  test('checks actual page and Worker values on a disposable non-network page', async () => {
    const { context, page } = fixture();
    await verifyAppliedContextFingerprint(context, identity);
    expect(page.goto.mock.calls[0][0]).toMatch(/^data:text\/html/);
    expect(page.close).toHaveBeenCalled();
  });

  test.each(['userAgent', 'appVersion', 'platform', 'oscpu', 'hardwareConcurrency', 'screen', 'language', 'firstLanguage', 'timezone', 'devicePixelRatio'])(
    'rejects an ignored setter / mismatched page.%s before exposing Context', async (key) => {
      const actual = signals();
      actual[key] = 'incorrect';
      const { context, page } = fixture(actual);
      await expect(createInitializedContext({
        browser: { newContext: async () => context }, userId: 'user', contextOptions: {},
        initializers: [({ context }) => verifyAppliedContextFingerprint(context, identity)],
      })).rejects.toThrow(`page.${key}`);
      expect(page.close).toHaveBeenCalled();
      expect(context.close).toHaveBeenCalled();
    },
  );

  test('rejects Worker disagreement and screen/CSS disagreement', () => {
    const actual = signals();
    actual.worker.language = 'ja-JP';
    expect(() => assertObservedFingerprint(actual, identity)).toThrow(/worker.language/);
    actual.worker.language = identity.locale;
    actual.screenCss = [false, true];
    expect(() => assertObservedFingerprint(actual, identity)).toThrow(/CSS/);
  });

  test('rejects a throwing init script even if its other values appear correct', async () => {
    const { context, page } = fixture();
    page.goto.mockImplementation(async () => page.on.mock.calls[0][1](new Error('setter failed')));
    await expect(verifyAppliedContextFingerprint(context, identity)).rejects.toThrow(/page error/);
    expect(page.close).toHaveBeenCalled();
  });

  test('bounds verification time and closes the disposable page on timeout', async () => {
    const { context, page } = fixture();
    page.evaluate.mockImplementation(() => new Promise(() => {}));
    await expect(verifyAppliedContextFingerprint(context, identity, { timeoutMs: 20 })).rejects.toThrow(/timed out/);
    expect(page.close).toHaveBeenCalled();
  });
});
