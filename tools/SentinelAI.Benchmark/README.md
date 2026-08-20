# sentinelai-benchmark

SEC-39: precision and recall per category for SentinelAI, SonarQube and Snyk over one shared
ground-truth corpus.

```bash
dotnet run --project tools/SentinelAI.Benchmark -- --corpus tools/SentinelAI.Benchmark/sample-corpus
```

Full documentation — corpus layout, the label format, the matching rule, and what the numbers can
and cannot be read as — is in [`docs/Benchmark_Precision_Recall.md`](../../docs/Benchmark_Precision_Recall.md).

## `sample-corpus/`

A worked example: six labels over one project, both polarities, and results in both accepted
formats (SentinelAI's own JSON, SonarQube and Snyk as SARIF).

**It is not the SEC-38 corpus** and no figure from it should be quoted. It exists so the report's
shape can be seen, and so the runner is exercised end to end by something committed here rather
than only by a corpus that lives in another repository. The real corpus is in
`sentinelai-fixtures`.

The sample is deliberately built so every branch of the report shows up in one run: a true
positive, a false positive on a clean label, a false negative, an unlabelled finding, a category
that only one tool covers, and enough C# labels to trigger the ground-truth-gap caveat.
