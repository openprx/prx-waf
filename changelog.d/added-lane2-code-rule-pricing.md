- **The eighteen code-decided Lane 2 rules have prices.** `docs/lane2-rule-pricing.md`
  gains a section for them: fifteen priced by taking each away from the shipped
  posture, three by switching each on. Baseline shadow 139/10/2, enforce 75/2/2,
  reproduced in both directions.

  `xss.script_tag` is the most expensive rule in the inventory and the most
  valuable — **eight detections and two false positives**, at an identical score
  of 45 on both, so no threshold separates them. `xss.event_handler` carries four
  detections, a block and the third false positive. Taking both away is measured
  as its own run rather than summed: shadow 139 → **127**, false positives 10 →
  **7**, one block lost, blocking false positives unmoved. The five SQL-AST
  structures carry five of the corpus's seventy-five blocks and five detections
  on ten distinct rows, and two of the five carry blocks and no detection at
  all — the corroborating half of a two-detector family doing exactly what it is
  weighted to do.

  Of the three that shipped off behind a `#[cfg(test)]` constructor,
  `xss.object_embed` costs the eleventh false positive — a CMS page embedding a
  hosted PDF — for no detection. `xss.base_href` reads as free and is not: the
  corpus carries its shape, and `xss.script_tag` outranks it on the same field,
  so with the masking rule switched off it flags that row at 40.
  `xss.dangling_open_tag` scores one benign row under the line and nothing else.

  Two rules fire on nothing in either half: `xss.data_html_url`, because the one
  corpus row with a `data:text/html` payload delivers it in a query parameter
  rather than a URL attribute, and `deser.py_pickle_dangerous_global`, which has
  still never been observed firing. Both are recorded as no information rather
  than as clean.
