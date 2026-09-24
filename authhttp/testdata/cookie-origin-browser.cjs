const assert = require('node:assert/strict');
const { chromium } = require(process.env.AUTHKIT_PLAYWRIGHT_MODULE || '@playwright/test');
const victim = process.env.AUTHKIT_BROWSER_VICTIM_URL;
const attacker = process.env.AUTHKIT_BROWSER_ATTACKER_URL;
(async () => {
  const browser = await chromium.launch({ headless: true, executablePath: process.env.AUTHKIT_BROWSER_EXECUTABLE || undefined });
  try {
    const context = await browser.newContext({ ignoreHTTPSErrors: true });
    const page = await context.newPage();
    await page.goto(victim);
    const login = await page.evaluate(async () => {
      const response = await fetch('/api/v1/password/login', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ identifier: 'browser-victim@example.test', password: 'Victim-password-12345' }),
      });
      return { status: response.status, tokens: await response.json() };
    });
    assert.equal(login.status, 200);
    assert.ok(login.tokens.access_token);
    assert.equal(login.tokens.refresh_token, undefined);
    const cookie = async () => (await context.cookies()).find(c => c.name === '__Host-authkit_rt');
    const original = await cookie();
    assert.ok(original && original.httpOnly && original.secure);
    assert.equal(original.sameSite, 'Lax');
    assert.equal(original.path, '/');
    for (const encoding of ['text/plain', 'application/x-www-form-urlencoded', 'multipart/form-data']) {
      await page.goto(`${attacker}/?encoding=${encodeURIComponent(encoding)}`);
      const responsePromise = page.waitForResponse(r => r.url() === `${victim}/api/v1/password/login` && r.request().method() === 'POST');
      await page.getByRole('button', { name: 'Submit' }).click();
      const response = await responsePromise;
      assert.equal(response.status(), 400, encoding);
      const headers = await response.request().allHeaders();
      assert.equal(headers.origin, attacker);
      assert.equal(headers['sec-fetch-site'], 'cross-site');
      assert.deepEqual(await cookie(), original, `${encoding} must preserve the existing cookie`);
      console.log(`${encoding}: cross-site browser POST refused; existing cookie unchanged`);
    }
    await page.goto(victim);
    const refreshed = await page.evaluate(async () => {
      const response = await fetch('/api/v1/token', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ grant_type: 'refresh_token' }) });
      return { status: response.status, tokens: await response.json() };
    });
    assert.equal(refreshed.status, 200);
    assert.ok(refreshed.tokens.access_token);
    const rotated = await cookie();
    assert.notEqual(rotated.value, original.value);
    const logout = await page.evaluate(async access => (await fetch('/api/v1/logout', { method: 'DELETE', headers: { Authorization: `Bearer ${access}` } })).status, refreshed.tokens.access_token);
    assert.equal(logout, 204);
    assert.equal(await cookie(), undefined);
    await context.addCookies([rotated]);
    const replay = await page.evaluate(async () => (await fetch('/api/v1/token', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ grant_type: 'refresh_token' }) })).status);
    assert.equal(replay, 401);
    console.log('same-origin login, rotation and logout succeed; revoked refresh replay fails');
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
