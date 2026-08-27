# Print check

Manual checklist. CI cannot verify that the report prints well, so this
runs once per meaningful layout or stylesheet change. Do not skip it and
do not claim CI covers it.

**When:** any change to the report template, the stylesheet, chart
markup, or the truncation rule.

**Setup:** render a multi-page report from the mixed-tree fixture (must
include at least one file of each status, one file whose findings span a
page break, and enough clean files to exercise appendix A), then open
print preview in **both** Chrome and Firefox.

## Checklist

- [ ] **Charts render.** Level bars, the coverage strip, and the navy
      table header fills appear in print preview, not blank. If blank,
      `print-color-adjust: exact` is missing or was dropped.
- [ ] **The level chart totals the Findings card.** Every finding gets a
      bar, including the ones with no level stated. A chart summing to
      less than the number printed above it is the defect this report
      exists in order not to have.
- [ ] **Page breaks respect findings.** No finding is separated from its
      evidence rows across a page boundary.
- [ ] **Table headers repeat.** Asset / Level / Conf. headers appear at
      the top of every continued page, not just the first.
- [ ] **Continued file sections are identifiable.** A page that starts
      mid-file names the file at the top.
- [ ] **No clipped columns.** Long paths, long signature ids, and
      260-character filenames wrap or truncate visibly, never run off the
      right margin.
- [ ] **Evidence descriptions are readable.** The description column in
      the evidence rows holds whole words on a line. One character per
      line means the nested table has outgrown the cell around it, which
      the browser does not report as an overflow.
- [ ] **Screen matches paper.** The on-screen sheet is A4 wide, so a
      line that fits in the browser fits in the PDF. If they disagree,
      the preview is not a preview.
- [ ] **Cover is its own sheet.** Page 1 carries the title, the directory
      scanned, the provenance table, and nothing else. The claim note sits
      at the foot of the sheet, not directly under the table. Nothing from
      the summary bleeds onto it.
- [ ] **Summary is its own sheet.** Page 2 holds the metrics, the level
      chart, and coverage. Expansions never push it onto a third sheet;
      an expansion that does not fit is cut, not carried.
- [ ] **Provenance on every page.** Tool version, signature version, and
      CBOM hash. The running head puts it at the top of each sheet; the
      fixed footer is what carries it onto the *continuation* pages of a
      long findings section, and that is the item Firefox is most likely
      to fail, since it treats fixed elements differently from Chrome.
      Page numbers are **not** the document's job (design §8); check them
      by enabling the browser's own headers and footers.
- [ ] **Exported with Save as PDF, not a print driver.** In Chrome or
      Edge the destination must be *Save as PDF* with Background graphics
      on. *Microsoft Print to PDF* is a virtual printer: it applies the
      driver's own hardware margins on top of `@page`, drops background
      fills, and snaps hairlines. A PDF whose `/Producer` reads
      `Microsoft: Print To PDF` proves nothing about this stylesheet.
- [ ] **Grayscale legibility.** Print or export in grayscale: every
      status is still readable from its text, coverage segments are still
      distinguishable, and the level 0 rows are still identifiable
      without color.
- [ ] **Counts agree.** Summary numbers, coverage table numbers, and the
      appendix line agree with the source CBOM. Exact counts, not
      percentages.
- [ ] **Truncation copy is correct.** Appendix A either lists the clean
      files or states the omission with the threshold named.
- [ ] **No orphaned headings.** No section heading sits alone at the
      bottom of a page.
- [ ] **Every table keeps all four rules.** Look at the left and right
      edges of the widest tables. A collapsed table draws half its outer
      border outside its own box, so one flush against the page-area
      boundary loses those rules to the print clip — the report's own
      frame, missing, on every page. The 1mm of sheet padding is what
      prevents it.
- [ ] **Margins hold.** `12mm 12mm 14mm` on A4 — split as an 11/11/13mm
      `@page` margin plus 1mm of sheet padding, so check the total, not
      the declaration. Nothing collides with the running footer. These
      are deliberately tight — paper costs money — so this is the check
      most likely to catch a regression.

## Record

Note the date, the commit, and the two browser versions checked in the PR
description. If something failed and was fixed, say what it was: this is
the only place that history exists.
