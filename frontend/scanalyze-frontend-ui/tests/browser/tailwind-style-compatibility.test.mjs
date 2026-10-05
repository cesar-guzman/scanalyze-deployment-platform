import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { after, before, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import postcss from 'postcss';
import { chromium, expect } from '@playwright/test';
import postcssConfig from '../../postcss.config.js';

// Compile the product stylesheet with its configured plugins. These synthetic
// compositions exercise the existing UI's CSS contract without loading the app,
// its authentication/configuration modules, or any remote resources.
const stylesheet = fileURLToPath(new URL('../../src/index.css', import.meta.url));
const caseOptions = { timeout: 15_000 };
let browser;
let compiledCss;

const fixture = `<!doctype html>
  <meta charset="utf-8">
  <title>Synthetic Tailwind compatibility</title>
  <main id="root">
    <section id="card" class="glass-container p-6">
      <p id="mono" class="font-mono text-sm">Synthetic document reference</p>
    </section>
    <section>
      <button id="primary" class="btn-primary transition-transform hover:-translate-y-0.5">Primary</button>
      <button id="outline" class="btn-outline">Outline</button>
      <button id="danger" class="btn-danger">Danger</button>
      <button id="generic">Generic</button>
      <button id="disabled" class="btn-primary" disabled>Pending</button>
      <button id="explicit-disabled" class="btn-outline disabled:cursor-not-allowed" disabled>Unavailable</button>
    </section>
    <section>
      <input id="analytics-input" class="input-field py-1 px-3 text-sm flex-1 m-0 min-w-[120px]" placeholder="Synthetic batch filter">
      <select id="analytics-select" class="input-field py-1 px-3 text-sm min-w-[140px] m-0"><option>Synthetic range</option></select>
      <input id="file" type="file" multiple aria-label="Synthetic recovery originals">
      <span id="field-control" style="background-color: Field">Native field reference</span>
      <div id="native-reference"></div>
    </section>
    <section>
      <div id="small-shadow" class="shadow-xs">Small shadow</div>
      <div id="inner-shadow" class="inset-shadow-sm">Inset shadow</div>
      <div id="backdrop" class="backdrop-blur-xs">Backdrop blur</div>
      <div id="decoration" class="blur-[80px]">Decorative blur</div>
      <div id="radius" class="rounded">Task icon radius</div>
    </section>
    <section id="upload-stack" class="flex flex-col items-center gap-4 text-slate-300 cursor-pointer">
      <svg class="w-16 h-16 opacity-75" viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3v18" /></svg>
      <p class="font-medium text-lg">Synthetic file selection</p>
      <p class="text-sm opacity-75">Synthetic file instructions</p>
      <button class="px-6 py-2 rounded-full bg-white/10 hover:bg-white/20 font-semibold transition-colors">Browse synthetic files</button>
    </section>
    <section id="responsive" class="grid grid-cols-1 md:grid-cols-2 gap-4">
      <div>First synthetic task</div><div>Second synthetic task</div>
    </section>
  </main>`;

before(async () => {
  const plugins = [];
  for (const [name, options] of Object.entries(postcssConfig.plugins)) {
    if (options === false) continue;
    const { default: createPlugin } = await import(name);
    plugins.push(createPlugin(options));
  }
  const result = await postcss(plugins).process(await readFile(stylesheet, 'utf8'), {
    from: stylesheet, map: false,
  });
  compiledCss = result.css;
  browser = await chromium.launch({ headless: true });
});

after(async () => { await browser?.close(); });

async function openFixture(t, viewport = { width: 1024, height: 768 }) {
  const context = await browser.newContext({ viewport, colorScheme: 'dark', serviceWorkers: 'block' });
  const requests = [];
  const errors = [];
  await context.route('**/*', route => route.abort());
  const page = await context.newPage();
  page.setDefaultTimeout(5000);
  page.on('request', request => requests.push(request.url()));
  page.on('pageerror', error => errors.push(error.message));
  t.after(async () => {
    try {
      assert.deepEqual(requests, [], 'the CSS fixture must not request external resources');
      assert.deepEqual(errors, [], 'the static fixture must have no browser errors');
    } finally {
      await context.close();
    }
  });
  await page.setContent(fixture);
  await page.addStyleTag({ content: compiledCss });
  await settleTransitions(page);
  return page;
}

async function settleTransitions(page) {
  await page.evaluate(async () => {
    // Flush styles before enumerating transitions triggered by CSS insertion or
    // focus. Await the browser's animation completion rather than sampling an
    // intermediate frame or disabling the product's transition behavior.
    document.body.getBoundingClientRect();
    await Promise.all(document.getAnimations().map(animation => animation.finished));
  });
}

async function styles(page, selector, properties, pseudo = null) {
  return page.locator(selector).evaluate((element, { properties, pseudo }) => {
    const computed = getComputedStyle(element, pseudo);
    return Object.fromEntries(properties.map(property => [property, computed.getPropertyValue(property)]));
  }, { properties, pseudo });
}

test('real CSS preserves the dark palette, typography, card and button variants', caseOptions, async t => {
  const page = await openFixture(t);
  assert.deepEqual(await styles(page, 'body', ['background-color', 'color', 'font-family', 'display', 'flex-direction']), {
    'background-color': 'rgb(2, 6, 23)', color: 'rgb(226, 232, 240)',
    'font-family': 'Inter, system-ui, sans-serif', display: 'flex', 'flex-direction': 'column',
  });
  assert.deepEqual(await styles(page, '#card', ['background-color', 'border-color', 'border-width', 'border-radius']), {
    'background-color': 'rgb(15, 23, 42)', 'border-color': 'rgb(30, 41, 59)',
    'border-width': '1px', 'border-radius': '12px',
  });
  assert.deepEqual(await styles(page, '#mono', ['font-family', 'font-size', 'line-height']), {
    'font-family': 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
    'font-size': '14px', 'line-height': '20px',
  });
  for (const [id, background, color, border] of [
    ['primary', 'rgb(79, 70, 229)', 'rgb(255, 255, 255)', 'rgba(0, 0, 0, 0)'],
    ['outline', 'rgba(0, 0, 0, 0)', 'rgb(226, 232, 240)', 'rgb(51, 65, 85)'],
    ['danger', 'rgb(225, 29, 72)', 'rgb(255, 255, 255)', 'rgba(0, 0, 0, 0)'],
  ]) {
    assert.deepEqual(await styles(page, `#${id}`, [
      'background-color', 'color', 'border-color', 'padding', 'border-radius', 'font-weight', 'cursor',
    ]), {
      'background-color': background, color, 'border-color': border, padding: '8px 16px',
      'border-radius': '8px', 'font-weight': '500', cursor: 'pointer',
    }, `${id} button`);
  }
});

test('disabled buttons retain the default cursor and explicit unavailable cursor', caseOptions, async t => {
  const page = await openFixture(t);
  assert.deepEqual(await styles(page, '#disabled', ['cursor']), { cursor: 'default' });
  assert.deepEqual(await styles(page, '#explicit-disabled', ['cursor']), { cursor: 'not-allowed' });
});

test('keyboard focus shows each button ring with the original offset and color', caseOptions, async t => {
  const page = await openFixture(t);
  for (const [id, expectedColor] of [
    ['primary', [99, 102, 241, 255]], ['outline', [148, 163, 184, 255]],
    ['danger', [244, 63, 94, 255]], ['generic', [59, 130, 246, 128]],
  ]) {
    await page.keyboard.press('Tab');
    await expect(page.locator(`#${id}`)).toBeFocused();
    await settleTransitions(page);
    const focus = await page.locator(`#${id}`).evaluate(element => {
      const computed = getComputedStyle(element);
      const canvas = document.createElement('canvas');
      canvas.width = canvas.height = 1;
      const context = canvas.getContext('2d');
      context.fillStyle = computed.getPropertyValue('--tw-ring-color');
      context.fillRect(0, 0, 1, 1);
      return { visible: element.matches(':focus-visible'), shadow: computed.boxShadow,
        color: [...context.getImageData(0, 0, 1, 1).data] };
    });
    assert.equal(focus.visible, true, `${id} receives keyboard-visible focus`);
    assert.match(focus.shadow, /rgb\(2, 6, 23\) 0px 0px 0px 2px/, `${id} has the dark 2px ring offset`);
    assert.match(focus.shadow, /0px 0px 0px 4px/, `${id} has a visible 2px ring beyond its offset`);
    focus.color.forEach((channel, index) => assert.ok(Math.abs(channel - expectedColor[index]) <= 1,
      `${id} ring channel ${index}: expected ${expectedColor[index]}, received ${channel}`));
  }
});

test('outline-hidden retains a visible native outline in forced colors', caseOptions, async t => {
  const page = await openFixture(t);
  await page.emulateMedia({ forcedColors: 'active' });
  await page.keyboard.press('Tab');
  await expect(page.locator('#primary')).toBeFocused();
  const focus = await styles(page, '#primary', ['outline-style', 'outline-width', 'outline-color']);
  assert.notEqual(focus['outline-style'], 'none');
  assert.ok(parseFloat(focus['outline-width']) > 0, 'keyboard focus must remain visible without colored box shadows');
  assert.notEqual(focus['outline-color'], 'rgba(0, 0, 0, 0)');
});

test('Analytics filters retain the native Field background and opaque placeholders', caseOptions, async t => {
  const page = await openFixture(t);
  const reference = await styles(page, '#field-control', ['background-color']);
  assert.notEqual(reference['background-color'], 'rgba(0, 0, 0, 0)');
  for (const id of ['analytics-input', 'analytics-select']) {
    assert.deepEqual(await styles(page, `#${id}`, ['background-color']), reference, `${id} keeps the native background`);
  }
  assert.deepEqual(await styles(page, '#analytics-input', ['color', 'opacity'], '::placeholder'), {
    color: 'rgb(156, 163, 175)', opacity: '1',
  });
});

test('recovery file selectors retain native button borders and padding', caseOptions, async t => {
  const page = await openFixture(t);
  const button = await styles(page, '#file', ['border-width', 'padding', 'background-color', 'font-family', 'appearance'], '::file-selector-button');
  const native = await page.locator('#native-reference').evaluate(host => {
    const shadow = host.attachShadow({ mode: 'open' });
    shadow.innerHTML = '<style>input, input::file-selector-button { font: inherit; }</style><input type="file">';
    const computed = getComputedStyle(shadow.querySelector('input'), '::file-selector-button');
    return { border: computed.borderWidth, padding: computed.padding, background: computed.backgroundColor };
  });
  assert.ok(parseFloat(native.border) > 0, 'native file buttons have a visible border');
  assert.ok(parseFloat(native.padding) > 0, 'native file buttons have internal padding');
  assert.equal(button['border-width'], native.border);
  assert.equal(button.padding, native.padding);
  assert.equal(button['background-color'], native.background);
  assert.equal(button['font-family'], 'Inter, system-ui, sans-serif');
  assert.equal(button.appearance, 'button');
});

test('mapped shadows, backdrop blur and task radii preserve their rendered values', caseOptions, async t => {
  const page = await openFixture(t);
  const small = await styles(page, '#small-shadow', ['box-shadow']);
  const inner = await styles(page, '#inner-shadow', ['box-shadow']);
  assert.match(small['box-shadow'], /rgba\(0, 0, 0, 0\.05\) 0px 1px 2px 0px/);
  assert.match(inner['box-shadow'], /rgba\(0, 0, 0, 0\.05\) 0px 2px 4px 0px inset/);
  assert.deepEqual(await styles(page, '#backdrop', ['backdrop-filter']), { 'backdrop-filter': 'blur(4px)' });
  assert.deepEqual(await styles(page, '#decoration', ['filter']), { filter: 'blur(80px)' });
  assert.deepEqual(await styles(page, '#radius', ['border-radius']), { 'border-radius': '4px' });
});

for (const [width, columns] of [[375, 1], [1024, 2]]) {
  test(`file selection keeps three 16px gaps and ${columns} task column(s) at ${width}px`, caseOptions, async t => {
    const page = await openFixture(t, { width, height: 768 });
    const gaps = await page.locator('#upload-stack').evaluate(element => {
      const children = [...element.children].map(child => child.getBoundingClientRect());
      return children.slice(1).map((child, index) => child.top - children[index].bottom);
    });
    assert.deepEqual(gaps, [16, 16, 16], 'the selection button must not introduce an extra top margin');
    const layout = await page.locator('#responsive').evaluate(element => {
      const children = [...element.children].map(child => child.getBoundingClientRect());
      return { columns: getComputedStyle(element).gridTemplateColumns.split(' ').length,
        sameRow: children[0].top === children[1].top, width: element.getBoundingClientRect().width };
    });
    assert.equal(layout.columns, columns);
    assert.equal(layout.sameRow, columns === 2);
    assert.equal(layout.width, width, 'the grid should fit its viewport');
  });
}

test('hover keeps the original primary color and 2px button lift', caseOptions, async t => {
  const page = await openFixture(t);
  const button = page.locator('#primary');
  const initial = await button.boundingBox();
  await button.hover();
  await expect.poll(async () => (await button.boundingBox()).y).toBe(initial.y - 2);
  await expect.poll(async () => (await styles(page, '#primary', ['background-color']))['background-color'])
    .toBe('rgb(99, 102, 241)');
  await page.mouse.move(0, 0);
  await expect.poll(async () => (await button.boundingBox()).y).toBe(initial.y);
});
