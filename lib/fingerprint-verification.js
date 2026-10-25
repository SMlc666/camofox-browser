import { isDeepStrictEqual } from 'node:util';

export function expectedFingerprintSignals(identity) {
  return {
    userAgent: identity.userAgent,
    appVersion: identity.appVersion,
    platform: identity.platform,
    oscpu: identity.oscpu,
    hardwareConcurrency: identity.hardwareConcurrency,
    screen: [identity.screen.width, identity.screen.height, identity.screen.colorDepth],
    language: identity.locale,
    firstLanguage: identity.locale,
    // IANA aliases can be canonicalized by Intl (e.g. US/Eastern).
    timezone: new Intl.DateTimeFormat('en-US', { timeZone: identity.timezone }).resolvedOptions().timeZone,
    devicePixelRatio: identity.screen.deviceScaleFactor,
  };
}

export function assertObservedFingerprint(actual, identity) {
  const expected = expectedFingerprintSignals(identity);
  for (const [key, value] of Object.entries(expected)) {
    if (!isDeepStrictEqual(actual?.[key], value)) {
      throw new Error(`native fingerprint verification failed: page.${key} does not match the persisted identity`);
    }
  }
  for (const key of ['userAgent', 'platform', 'hardwareConcurrency', 'language', 'firstLanguage', 'timezone']) {
    if (!isDeepStrictEqual(actual?.worker?.[key], expected[key])) {
      throw new Error(`native fingerprint verification failed: worker.${key} does not match the persisted identity`);
    }
  }
  if (!isDeepStrictEqual(actual?.screenCss, [true, true])) {
    throw new Error('native fingerprint verification failed: screen and CSS device media queries disagree');
  }
}

/** Run only against disposable data/blob pages, never a user's network origin. */
export async function verifyAppliedContextFingerprint(context, identity, { timeoutMs = 10000 } = {}) {
  let page;
  let timeout;
  const errors = [];
  try {
    const verify = (async () => {
      page = await context.newPage();
      page.on('pageerror', (error) => errors.push(error.message));
      await page.goto('data:text/html,<!doctype html><title>native identity verification</title>', { timeout: timeoutMs });
      const actual = await page.evaluate(async () => {
        const worker = await new Promise((resolve, reject) => {
          const source = `onmessage = () => postMessage({ userAgent: navigator.userAgent, platform: navigator.platform, hardwareConcurrency: navigator.hardwareConcurrency, language: navigator.language, firstLanguage: navigator.languages[0], timezone: Intl.DateTimeFormat().resolvedOptions().timeZone });`;
          const url = URL.createObjectURL(new Blob([source], { type: 'text/javascript' }));
          const instance = new Worker(url);
          const finish = () => { clearTimeout(timer); instance.terminate(); URL.revokeObjectURL(url); };
          const timer = setTimeout(() => { finish(); reject(new Error('native identity Worker verification timed out')); }, 5000);
          instance.onmessage = (event) => { finish(); resolve(event.data); };
          instance.onerror = () => { finish(); reject(new Error('native identity Worker verification failed')); };
          instance.postMessage(null);
        });
        return {
          userAgent: navigator.userAgent,
          appVersion: navigator.appVersion,
          platform: navigator.platform,
          oscpu: navigator.oscpu,
          hardwareConcurrency: navigator.hardwareConcurrency,
          screen: [screen.width, screen.height, screen.colorDepth],
          language: navigator.language,
          firstLanguage: navigator.languages[0],
          timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
          devicePixelRatio,
          screenCss: [matchMedia(`(device-width: ${screen.width}px)`).matches, matchMedia(`(device-height: ${screen.height}px)`).matches],
          worker,
        };
      });
      if (errors.length > 0) throw new Error('native fingerprint initialization raised a page error');
      assertObservedFingerprint(actual, identity);
    })();
    await Promise.race([
      verify,
      new Promise((_, reject) => { timeout = setTimeout(() => reject(new Error('native fingerprint verification timed out')), timeoutMs); }),
    ]);
  } finally {
    clearTimeout(timeout);
    await Promise.resolve(page?.close()).catch(() => {});
  }
}
