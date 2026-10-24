export async function createInitializedContext({ browser, userId, contextOptions, initializers }) {
  let context;
  try {
    context = await browser.newContext(contextOptions);
    for (const initialize of initializers) {
      await initialize({ userId, context, contextOptions });
    }
    return context;
  } catch (err) {
    await Promise.resolve(context?.close()).catch(() => {});
    throw err;
  }
}
