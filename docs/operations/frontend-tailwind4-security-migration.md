# Frontend build dependency remediation

The postmerge reproducibility check for PR130 stopped at the frontend npm audit.
GHSA-vfj7-8cjw-p6xm affects the installed braces 3.0.3 package. Tailwind 3.4.19
introduces it through chokidar and micromatch/fast-glob. No patched braces release
was available when the candidate was prepared. The confirmed source-to-sink path
is committed build-time content globs; customer-controlled input reaching this
path in the deployed browser application has not been established.

## Change and compatibility

Pin Tailwind and its PostCSS integration to 4.3.3, regenerate the lockfile, and
remove the unused standalone autoprefixer plugin. Tailwind 4 performs the import
and prefix handling. The npm audit threshold and CI gates remain unchanged.

CSS imports Tailwind directly and scans only the existing src tree and index.html.
The old JavaScript config is replaced by CSS theme values and variants.
Preserve existing font stacks, colors, class-based dark mode, hover behavior,
native Analytics filters, file chooser buttons, and disabled-button cursors.
Map renamed shadow, blur, outline and shrink utilities to their previous values;
explicit sRGB gradients preserve the previous interpolation. Use gap utilities
on flex containers and remove the redundant upload button margin.

Tailwind 4 targets Safari 16.4+, Chrome 111+, and Firefox 128+. This migration
changes the supported browser floor. Validate those browser requirements before
releasing to users who require older browsers.

## Validation

From frontend/scanalyze-frontend-ui, using a supported Node version:

~~~bash
npm ci
npm run check
npm run test:browser
npm run audit
~~~

The style regression harness compiles the actual src/index.css through the
configured PostCSS plugin and exercises synthetic DOM controls in Chromium.
It does not authenticate, call cloud APIs, or load customer documents.
Existing browser tests cover the real frontend hooks and renderers with
synthetic clients. Separate validation in Safari and Firefox remains necessary
before claiming browser compatibility beyond the tested Chromium version.

The local candidate was prepared from byte-matched copied frontend source
because the existing shared Git object packs were dataless placeholders.
A patch must be applied to a verified, clean checkout of the merged source
before publication. Local checks do not establish remote CI success.

## Review, release and rollback

Use a new issue, branch, worktree and PR; PR130 is already merged.
Verify the new published SHA, review approval, and terminal CI results.
After merge, check workflows for the exact merge SHA before continuing deployment.

Rollback by reverting the reviewed migration commit and restoring the prior
package/config/CSS files together. The previous dependency graph still contains
the known advisory, so a rollback must not be presented as security remediation
or a cleared release gate.

This change does not deploy the application or satisfy checksum custody,
authority installation, HTTPS, identity, or authenticated runtime acceptance.

References:

- [braces advisory](https://github.com/advisories/GHSA-vfj7-8cjw-p6xm)
- [Tailwind upgrade guide](https://tailwindcss.com/docs/upgrade-guide)
