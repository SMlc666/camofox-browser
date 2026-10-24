import { describe, expect, jest, test } from '@jest/globals';
import { createInitializedContext } from '../../lib/session-context.js';

describe('session context initializers', () => {
  test('runs each initializer before returning the new browser context', async () => {
    const context = { close: jest.fn() };
    const browser = { newContext: jest.fn(async () => context) };
    const calls = [];
    const initializers = [
      async (payload) => calls.push(['fingerprint', payload]),
      async (payload) => calls.push(['other', payload]),
    ];
    const contextOptions = { locale: 'en-US' };

    const result = await createInitializedContext({ browser, userId: 'user-1', contextOptions, initializers });

    expect(result).toBe(context);
    expect(browser.newContext).toHaveBeenCalledWith(contextOptions);
    expect(calls).toEqual([
      ['fingerprint', { userId: 'user-1', context, contextOptions }],
      ['other', { userId: 'user-1', context, contextOptions }],
    ]);
    expect(context.close).not.toHaveBeenCalled();
  });

  test('closes a partially initialized context and preserves the initializer error', async () => {
    const error = new Error('native identity initialization failed');
    const context = { close: jest.fn(async () => {}) };
    const browser = { newContext: jest.fn(async () => context) };
    const initializers = [async () => { throw error; }];

    await expect(createInitializedContext({
      browser,
      userId: 'user-1',
      contextOptions: {},
      initializers,
    })).rejects.toBe(error);
    expect(context.close).toHaveBeenCalledTimes(1);
  });
});
