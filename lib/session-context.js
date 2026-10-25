export async function createInitializedContext({ browser, userId, contextOptions, initializers }) {
  let context;
  const steps = [...initializers];
  try {
    // Run after all session:creating hooks (including async storageState load),
    // but before browser.newContext can receive old cookies with a new identity.
    for (const initialize of steps) {
      await initialize.prepare?.({ userId, contextOptions });
    }
    context = await browser.newContext(contextOptions);
    for (const initialize of steps) {
      await initialize({ userId, context, contextOptions });
    }
    return context;
  } catch (err) {
    await Promise.resolve(context?.close()).catch(() => {});
    throw err;
  }
}
