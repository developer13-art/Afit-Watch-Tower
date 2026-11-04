# Brand artwork

| File | What it is | Weight |
| --- | --- | --- |
| `afit-emblem.png` | The AFIT WATCH TOWER emblem supplied by AFIT on 2026-11-03, carried at 512px with the dark surround around its rounded frame made transparent | 380 KB |
| `campus-night.generated.jpg` | AI-generated night view of a floodlit campus gate, used behind the splash and login screens | 94 KB |

**`afit-emblem.png` is AFIT's own artwork. `campus-night.generated.jpg` is not** — it was
generated for this redesign because no campus photography was supplied, and it is named
`.generated` so that status survives in the repository.

Both are served from `public/` instead of imported, so they stay out of the JavaScript bundle and
are fetched once, on the two entry screens that show them. The paths are read in one place —
`src/components/Brand.tsx`.

## Regenerating the derived icon set

`public/favicon.png`, `public/apple-touch-icon.png` and everything under
`android/app/src/main/res/` (launcher icons at five densities, adaptive-icon foregrounds, splash
screens, `ic_launcher_background.xml`) are **derived** from the emblem. Do not hand-edit them.
After dropping a new emblem in place, run:

```
python scripts/make_brand_assets.py [path/to/official_emblem.png]
```

With a source file it re-normalises the emblem first (strips the surround, crops, resizes to
512px); without one it rebuilds the derived set from the emblem already here. Requires Pillow.

The adaptive-icon foreground keeps the whole emblem inside the 66dp safe zone of the 108dp canvas
rather than letting the launcher's circular mask cut the wordmark off. The background colour is
sampled from the emblem's own dark field, so the frame reads as continuous with it.

The campus photograph is 720x1280 because it is only ever drawn full-bleed behind dimmed type on a
phone; a larger export buys nothing and costs a login screen's worth of bandwidth.
