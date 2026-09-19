---
name: False positive
about: A rule fired on content that is not a problem
labels: false-positive
---

**Rule** (e.g. `AGT-EXEC-001`):

**Content that triggered it:**

```
```

**Why it is not a finding:**

<!--
False positives are treated as bugs here. A rule that flags correct work gets
suppressed wholesale, and a suppressed rule catches nothing while looking like
it catches everything. A fix ships with a corpus case in agtmls-spec.
-->
