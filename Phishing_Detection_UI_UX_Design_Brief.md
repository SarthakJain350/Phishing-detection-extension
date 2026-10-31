# UI/UX Design Brief

## Phishing Attack Detector --- Chrome Extension

**Version:** 1.0\
**Status:** Design and implementation brief\
**Project timeline:** 15 days\
**Primary surfaces:** Chrome extension popup, Gmail inline result,
high-risk navigation interstitial\
**Implementation context:** React-based Chrome Manifest V3 extension,
FastAPI backend, PostgreSQL, Gemini-assisted analysis\
**Design direction:** Quiet Security --- editorial, restrained, clear,
and evidence-led

------------------------------------------------------------------------

## 1. Purpose

Design a compact, trustworthy phishing detection experience for
**Phishing Attack Detector**. It should help users make a safer decision
about a website or email without pretending that automated analysis is
infallible.

The interface must make four things easy to understand:

1.  **What is the result?** A classification and a risk score from
    0--100.
2.  **Why did it get that result?** A short list of concrete signals.
3.  **How complete is the analysis?** Complete, partial, or unavailable.
4.  **What should I do next?** Scan, inspect evidence, return to safety,
    or explicitly continue.

The score is a **risk indicator, not a calibrated probability**. Do not
label it "% chance of phishing."

## 2. Product and design principles

-   **Evidence before decoration:** lead with the result and strongest
    reasons, not a dashboard, chart, or AI animation.
-   **Progressive disclosure:** show the decision-critical information
    first; reveal technical details only when requested.
-   **Proportionate interruption:** use the interstitial only for
    high-risk outcomes supported by the detection policy. Keep
    lower-risk results inside the popup or Gmail panel.
-   **Failure is not safety:** a provider error, timeout, unsupported
    page, or extraction failure must never appear as a clean result.
-   **Plain language first:** describe observed signals, not opaque
    model reasoning.
-   **Privacy by default:** do not display or persist full page/email
    content in history. Analyze only the current page or open/selected
    message.
-   **One clear next action:** make the safest next step visually
    obvious and keep secondary actions quieter.
-   **Accessible by construction:** communicate status with text and
    iconography as well as colour; support keyboard navigation and
    visible focus.

## 3. Visual direction: Editorial Quiet Security

The selected style is **editorial**: warm off-white backgrounds, crisp
typography, generous but efficient spacing, thin borders, and restrained
teal. The design should feel like a considered security utility rather
than a generic AI product.

### Avoid

-   Gradients, neon colours, glow effects, glassmorphism, and blurred
    panels.
-   Decorative AI stars, robot mascots, fake terminal output, and
    animated scanning rings.
-   Large dashboard charts, speedometer gauges, or dramatic score
    animations.
-   A wall of pills, badges, metrics, or cards.
-   Overconfident labels such as "100% safe" or "Guaranteed phishing
    detection."

### Brand identity

Use a **small shield-and-link icon** beside the wordmark **Phishing
Attack Detector**. Keep the mark simple enough to render clearly at
Chrome toolbar size. The first release can use a consistent temporary
SVG/icon; a custom illustration system is not required.

-   Toolbar icon: recognisable silhouette at 16--32 px.
-   Popup header: icon + product name, with no large hero area.
-   Do not invent a slogan unless one is needed for the demo.

## 4. Colour system

Use the existing Quiet Security tokens consistently across the popup,
Gmail inline panel, settings, and interstitial.

  -----------------------------------------------------------------------
  Token                   Hex                     Intended use
  ----------------------- ----------------------- -----------------------
  `canvas`                `#F7F5F0`               Main light-mode
                                                  background

  `surface`               `#FFFFFF`               Panels and inputs

  `ink`                   `#17212B`               Primary text and
                                                  headings

  `muted`                 `#5F6B75`               Supporting text and
                                                  metadata

  `border`                `#D8DEE3`               Dividers, outlines, and
                                                  panel borders

  `teal`                  `#0F766E`               Primary action and
                                                  selected state

  `teal-soft`             `#E5F3F0`               Subtle neutral/positive
                                                  accent

  `amber`                 `#9A5B00`               Suspicious or caution
                                                  state

  `amber-soft`            `#FFF1D6`               Suspicious state
                                                  background

  `red`                   `#B42318`               High-risk/phishing
                                                  state

  `red-soft`              `#FDECEA`               High-risk background

  `slate-soft`            `#EDF1F4`               Informational, partial,
                                                  or unavailable state

  `focus`                 `#2563EB`               Keyboard focus ring
  -----------------------------------------------------------------------

### Colour and state rules

-   **Phishing / high risk:** red icon and label with `red-soft`
    background.
-   **Suspicious:** amber icon and label with `amber-soft` background.
-   **Likely legitimate:** neutral ink and a restrained teal accent. Do
    not use a triumphant green "SAFE" treatment.
-   **Partial / unavailable:** neutral slate styling and explicit status
    copy.
-   **Primary button:** teal fill with readable white text.
-   **Secondary button:** white surface, border, and ink text.
-   Do not use colour alone to communicate classification.
-   Do not map the score to probability or imply a level of certainty
    the model cannot support.

### Dark mode

The product must support a **dark mode**. Implement it as a token-based
theme, not as a second independent design. Provide a simple theme choice
in settings (`System`, `Light`, `Dark`) if time allows; otherwise use
`System` as the default and provide a manual override only if it can be
completed reliably.

Suggested dark tokens:

  Token            Suggested value   Use
  ---------------- ----------------- -----------------------
  `canvas-dark`    `#111820`         Main background
  `surface-dark`   `#19232D`         Panels and controls
  `ink-dark`       `#F3F5F7`         Primary text
  `muted-dark`     `#AAB5BF`         Secondary text
  `border-dark`    `#35424E`         Dividers and outlines
  `teal-dark`      `#5CC8B8`         Primary action/accent
  `amber-dark`     `#F2BE61`         Suspicious state
  `red-dark`       `#FF8178`         High-risk state

Use dark-state background variants that retain sufficient contrast. Test
red and amber combinations in both themes; do not blindly reuse the
light-theme background colours.

## 5. Typography, spacing, and components

-   Use the system UI font stack. Avoid decorative fonts.
-   Use an 8 px spacing rhythm; use 8--12 px corner radii.
-   Prefer thin borders over strong shadows.
-   Use sentence case for labels and buttons.
-   Use compact headings and readable body text; avoid oversized hero
    typography in the popup.
-   Keep the extension popup single-column and compact.
-   Keep buttons and controls comfortably clickable; maintain a visible
    keyboard focus ring.
-   Use a consistent icon set or simple inline SVGs. Do not mix
    unrelated icon styles.
-   Loading states should use restrained text and a small spinner or
    progress indicator; no animated scanning theatrics.

## 6. Information architecture

### Primary surfaces

1.  **Extension popup** --- scan current website, view the latest
    result, expand evidence, access recent scans and settings.
2.  **Gmail inline panel** --- scan the open/selected email and display
    its classification and evidence close to the message.
3.  **High-risk interstitial** --- warn before continuing to a
    destination classified as high risk, where the supported Chrome
    navigation flow allows it.
4.  **Simple settings/history view** --- automatic website scanning,
    theme, backend status, and a short list of recent scan summaries.

Do not add a full analytics dashboard, account system, onboarding
carousel, or elaborate settings hierarchy to the first release.

## 7. Surface A --- Extension popup

### Primary purpose

Let a user manually scan the current website and understand the latest
result quickly.

### Default state layout

1.  **Header:** small shield/link icon and "Phishing Attack Detector."
2.  **Current site:** hostname displayed prominently; truncate long
    values without hiding the domain ending.
3.  **Primary action:** `Scan current site`.
4.  **Result area:** shown after a scan; classification, numeric risk
    score, and a concise status line.
5.  **Progressive detail control:** `Why this result?` expands the
    evidence list and tool statuses.
6.  **Footer/navigation:** `Recent scans` and `Settings` as quiet
    secondary links.

### Progressive disclosure

**Collapsed result** should show: - Classification label: `Phishing`,
`Suspicious`, or `Likely legitimate`. - Risk score:
`Risk score: 82/100`. - Analysis status when not complete. - Up to two
strongest reasons. - A control such as `View all signals` or
`Why this result?`.

**Expanded result** may show: - Full list of concise evidence signals. -
Source labels such as URL heuristics, reputation check, or content
analysis. - Per-tool state where useful: `Complete`, `Timed out`,
`Unavailable`. - A brief explanation of the score: "Higher scores
indicate more risk; this is not a probability." - A `Rescan` action if
the current page has changed or the user requests another check.

Avoid exposing raw prompts, hidden model reasoning, provider stack
traces, or long technical payloads.

### Empty state copy

**Heading:** `Check this website`\
**Body:**
`Scan the current page for signals commonly associated with phishing.`\
**Primary button:** `Scan current site`

### Loading state copy

**Heading:** `Checking this website…`\
**Body:** `Reviewing the page and available reputation signals.`

Do not imply that a result is final until the backend returns it. If the
request exceeds the expected wait, offer a clear retry option only when
safe to do so.

### Result copy examples

**High risk** - Label: `Phishing risk detected` - Score:
`Risk score: 86/100` - Summary:
`Several strong warning signs were found. Avoid entering passwords or payment details.` -
Detail control: `Why this result?`

**Suspicious** - Label: `Suspicious website` - Score:
`Risk score: 54/100` - Summary:
`Some warning signs were found, but the evidence is not conclusive.`

**Likely legitimate** - Label: `No strong phishing signals found` -
Score: `Risk score: 12/100` - Summary:
`The available checks found few warning signs. This does not guarantee the site is safe.`

**Partial analysis** - Label: `Partial analysis` - Summary:
`Some checks could not finish. Treat this result with caution.` - Show
the risk score only if the backend returns one under the defined
contract; make the incomplete status equally prominent.

**Unavailable** - Label: `Analysis unavailable` - Summary:
`The scan could not be completed. This is not a safe result.` - Action:
`Try again`

### Risk score treatment

Use a **large but restrained numeric score**, not a gauge: - Example:
`86 / 100` with the small label `Risk score`. - Place classification and
text next to it so the score is never the only signal. - No animated
count-up, radial meter, or percentage sign. - Score bands and warning
thresholds must come from the detection policy/configuration, not be
invented independently in the UI. - The UI should not recalculate the
score from individual signals.

## 8. Surface B --- Gmail inline result

### Primary purpose

Let users inspect the currently open or selected message without leaving
Gmail.

### Layout

-   Place a compact inline panel near the open message where feasible.
-   Keep Gmail's own message content and controls visually distinct; do
    not imitate Gmail's native security notices.
-   Include a clear `Scan this email` action before results exist.
-   After scanning, show classification, risk score, analysis status,
    and the two strongest reasons.
-   Expand `Why this result?` to reveal additional signals and tool
    availability.
-   If extraction is unsupported or the message is not available, show
    an explanatory unavailable state rather than an empty panel.

### Example high-risk result

**Phishing risk detected**\
`Risk score: 86/100`\
`The sender and message links contain warning signs commonly seen in phishing.`\
`Why this result?` · `Rescan email`

If a message contains suspicious links, show the hostname clearly. Do
not render a link in a way that makes the displayed destination
ambiguous.

### Gmail feasibility and fallback

Gmail's DOM and layout can change. Treat inline placement as a
feasibility checkpoint, not a guarantee. Build the simplest stable
integration first: 1. Detect an open message using supported extension
content-script techniques. 2. Add a restrained panel in a stable, tested
location. 3. Test message switching, collapsed threads, and viewport
changes. 4. If reliable inline placement cannot be achieved within the
schedule, use a clearly labelled extension-controlled panel or popup as
the fallback. Do not block Gmail or interfere with normal message
actions.

Do not scan the entire mailbox in the first release. Scan only the
open/selected message after a clear user action.

## 9. Surface C --- High-risk navigation interstitial

### Primary purpose

Give users a clear chance to return to safety before continuing to a
destination that the system classifies as high risk.

### Layout order

1.  Shield/link icon and product name.
2.  Strong heading: `This site may be a phishing attempt`.
3.  Destination hostname, displayed in a way that is easy to inspect.
4.  Risk score, e.g. `Risk score: 86/100`.
5.  One short summary and up to three strongest reasons.
6.  Primary action: `Go back to safety`.
7.  Secondary, visually quieter action: `Continue anyway`.
8.  Small note when analysis was partial or incomplete.

### Behaviour

-   The safer action must be visually dominant.
-   `Continue anyway` must require an explicit user action; do not make
    it the default.
-   Never imply that the interstitial can intercept every navigation.
    Use only a supported, tested Chrome extension mechanism.
-   Avoid redirect loops and ensure users can leave the warning screen.
-   Do not show the interstitial for every suspicious or uncertain
    result. Apply the agreed high-risk threshold.
-   If the analysis is unavailable, do not invent a high-risk score or
    present a provider failure as a phishing verdict. Use the defined
    fallback behaviour and explain that the site could not be assessed.

### Accessibility

-   Use a semantic heading, readable destination, and
    keyboard-accessible actions.
-   Ensure focus order is logical and the safer action is easy to reach.
-   Do not rely on red colour or an icon alone to explain the warning.

## 10. Surface D --- Simple history and settings

Keep this surface intentionally small.

### Settings

-   **Automatic website scanning:** on/off.
-   **Theme:** System / Light / Dark, if feasible within the timebox.
-   **Backend status:** Connected / Unavailable, with a short
    explanatory message.
-   **Privacy note:** "Scan history stores result metadata, not full
    page or email content by default."

### Recent scans

Show a short list of recent results with: - Classification label and
risk score. - Hostname or minimized target reference. - Timestamp. -
Analysis status when partial or unavailable.

Selecting an item may open its summary. Do not store full page text,
email body, full message content, or sensitive query parameters by
default. Include a clear empty state such as
`Your recent scans will appear here.`

Avoid advanced filters, charts, exports, and complex retention settings
in the initial version. If a clear-history action is implemented,
require confirmation and make its effect understandable.

## 11. State and component inventory

Build reusable components rather than separate bespoke versions for each
surface.

  -----------------------------------------------------------------------
  Component                           Purpose
  ----------------------------------- -----------------------------------
  `ProductHeader`                     Icon and product name

  `ClassificationLabel`               Text + icon for phishing,
                                      suspicious, likely legitimate

  `RiskScore`                         Numeric score with `Risk score`
                                      label

  `AnalysisStatus`                    Complete, partial, unavailable

  `EvidenceList`                      Concise signal/reason list

  `ToolStatusList`                    Optional provider/heuristic status
                                      details

  `PrimaryButton` / `SecondaryButton` Consistent action hierarchy

  `ScanLoadingState`                  Minimal progress feedback

  `EmptyState`                        Explains what the user can do

  `ErrorState`                        Explains failure and safe next step

  `ThemeTokens`                       Shared light/dark design tokens
  -----------------------------------------------------------------------

Required UI states: - Initial / no scan. - Scanning. - Complete result
for each classification. - Partial result. - Unavailable/error result. -
Empty recent history. - Backend unavailable. - Gmail message not
detected or unsupported. - Interstitial with supported continuation and
return actions.

## 12. Interaction and content rules

-   Use concise, direct copy and sentence case.
-   Explain observable signals, for example: "The displayed link text
    differs from its destination" or "The domain is newly observed by
    the reputation provider," only when that signal is actually
    returned.
-   Do not claim a signal exists unless the backend supplies it.
-   Avoid vague statements such as "AI found something suspicious"
    without evidence.
-   Never say "safe," "guaranteed," or "100% protected."
-   Do not expose model chain-of-thought or raw internal prompts.
-   Make retry behaviour explicit; avoid automatic repeated calls that
    could consume API quota.
-   Preserve partial results when one provider fails and clearly
    identify what could not be checked.
-   Treat all page and email text as untrusted content.

## 13. Accessibility and responsive behaviour

-   Meet WCAG AA contrast targets where applicable.
-   Pair every status colour with a label and icon.
-   Support keyboard-only interaction, visible focus, and logical tab
    order.
-   Provide accessible names for icon-only controls.
-   Respect reduced-motion preferences; the design uses minimal motion
    by default.
-   Keep popup content readable at narrow widths and avoid horizontal
    scrolling.
-   Test light and dark themes, long domains, long email subjects, long
    evidence text, and partial/unavailable states.
-   Ensure error and risk messages remain understandable when read by
    assistive technology.

## 14. Implementation constraints and 15-day scope

### Must have

-   Consistent token-based light and dark styling.
-   Popup manual scan and progressive result details.
-   Classification, risk score, evidence reasons, and analysis status.
-   Gmail scan action and inline result if feasibility checks pass.
-   High-risk warning surface using a supported and tested navigation
    mechanism.
-   Basic recent scan list and settings.
-   Loading, empty, partial, unavailable, and error states.
-   Keyboard focus, readable contrast, and responsive popup layout.

### Should have if time permits

-   Manual theme override in addition to system theme.
-   Clear-history action.
-   Expanded tool-status details.
-   Polished Gmail placement across common message states.

### Out of scope for the first release

-   Full security analytics dashboard.
-   User accounts and cloud sync.
-   Full mailbox scanning.
-   Elaborate onboarding.
-   Complex animation or illustration systems.
-   Guaranteed interception of all browser navigations.
-   Claims of perfect detection or a calibrated probability score.

### Suggested design/build sequence

1.  **Days 1--2:** agree API response contract, score semantics,
    classification labels, and failure states.
2.  **Days 3--5:** implement the popup shell, theme tokens,
    loading/empty/error states, and one complete scan-to-result path.
3.  **Days 6--8:** implement progressive evidence details, Gmail panel
    feasibility, and interstitial feasibility.
4.  **Days 9--10:** integrate all surfaces with real API responses and
    history.
5.  **Days 11--12:** test light/dark themes, accessibility, long
    content, provider failures, and navigation edge cases.
6.  **Days 13--14:** run regression tests and rehearse the demo.
7.  **Day 15:** freeze scope and fix only demo-blocking defects.

## 15. Acceptance checklist

The design is ready for the prototype demo when:

-   [ ] The product name and shield/link icon are consistent across
    surfaces.
-   [ ] The popup shows the current hostname and a clear scan action.
-   [ ] Results show a classification, numeric risk score, and concise
    evidence.
-   [ ] The UI explicitly states that the score is not a probability.
-   [ ] Evidence details are collapsed by default and can be expanded.
-   [ ] Partial and unavailable analysis are visually distinct from
    completed results.
-   [ ] Provider failure never produces a "safe" result.
-   [ ] Gmail scans only the open/selected message after a clear user
    action.
-   [ ] Gmail inline placement has a tested fallback if DOM placement is
    unstable.
-   [ ] The interstitial uses a supported navigation flow and offers
    `Go back to safety` and explicit `Continue anyway`.
-   [ ] Light and dark themes remain readable and consistent.
-   [ ] Recent history stores metadata/results, not full page or email
    content by default.
-   [ ] Keyboard focus, contrast, and status labels are tested.
-   [ ] No decorative AI dashboard patterns, gradients, neon effects, or
    unnecessary charts are present.

## 16. Instructions for the implementation agent

Use this brief alongside the existing PRD, TRD, and App Flow Document.
Inspect the current repository before changing files and preserve
working code. Implement the smallest end-to-end flow first, then reuse
its components across Gmail and the interstitial.

Do not invent API fields, score thresholds, signals, or provider
statuses in the UI. Use the agreed backend contract. Where a requested
browser behaviour is uncertain, run a short feasibility test and
implement the documented fallback rather than faking the behaviour.
Prioritise correctness, accessibility, privacy, and reliable failure
states over visual complexity.
