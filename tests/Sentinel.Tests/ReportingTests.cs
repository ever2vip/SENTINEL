using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Sentinel.Core;
using Sentinel.Infrastructure;
using static Sentinel.Tests.TestRunner;

namespace Sentinel.Tests;

internal static class ReportingTests
{
    public static async Task Run(TestRunner test)
    {
        var demo = new DemoLab().Create(CoreTests.FixtureTime);
        foreach (var kind in Enum.GetValues<ReportKind>())
        foreach (var format in Enum.GetValues<ReportFormat>())
        {
            await test.Check($"{kind} report exports a valid traceable {format} artifact", async () =>
            {
                using var temp = new TemporaryDirectory(); var path = temp.File($"report.{format.ToString().ToLowerInvariant()}");
                var artifact = await new ReportingEngine().ExportAsync(demo, kind, format, path);
                Equal(Path.GetFullPath(path), artifact.Path, "Artifact path"); Equal(kind, artifact.Kind, "Artifact kind"); Equal(format, artifact.Format, "Artifact format");
                var bytes = await File.ReadAllBytesAsync(path); Assert(bytes.Length > 200, "Empty or truncated report.");
                var text = Encoding.UTF8.GetString(bytes);
                if (format == ReportFormat.Json)
                {
                    using var document = JsonDocument.Parse(bytes); var root = document.RootElement;
                    Equal("sentinel.report.v1", root.GetProperty("SchemaVersion").GetString()!, "Report schema");
                    Equal(kind.ToString(), root.GetProperty("Kind").GetString()!, "Report semantic kind");
                    Equal(demo.Id, root.GetProperty("EnvironmentId").GetString()!, "Evidence environment");
                    Assert(root.GetProperty("Disclaimer").GetString()!.Contains("synthetic", StringComparison.OrdinalIgnoreCase), "Demo warning missing.");
                    Equal(new RiskEngine().Calculate(demo).GlobalScore, root.GetProperty("GlobalSecurityScore").GetDouble(), "Report score bypasses engine");
                    Assert(root.GetProperty("Sections").GetArrayLength() > 0, "Report has no content sections.");
                    foreach (var section in root.GetProperty("Sections").EnumerateArray())
                    foreach (var table in section.GetProperty("Tables").EnumerateArray())
                        Assert(table.GetProperty("Rows").EnumerateArray().All(row => row.GetArrayLength() == table.GetProperty("Columns").GetArrayLength()), "Report table cells do not align with headers.");
                }
                else if (format == ReportFormat.Html)
                {
                    Assert(text.StartsWith("<!doctype html>") && text.EndsWith("</html>") && text.Contains("Content-Security-Policy"), "HTML report is incomplete or lacks export security policy.");
                    Assert(text.Contains("synthetic", StringComparison.OrdinalIgnoreCase) && text.Contains(demo.Id), "HTML provenance missing.");
                }
                else if (format == ReportFormat.Csv)
                {
                    var rows = ParseCsv(text.TrimStart('\uFEFF'));
                    Assert(rows.Count > 10 && rows.All(x => x.Count == 5), "Structured CSV is malformed.");
                    Assert(rows.Any(x => x[3] == "Environment ID" && x[4] == demo.Id), "CSV provenance missing.");
                }
                else ValidatePdf(bytes);
                Assert(!Directory.EnumerateFiles(temp.Path, "*.tmp").Any(), "Export left a partial artifact.");
            });
        }
        await test.Check("Executive and technical narratives prioritize grouped remediation rather than an individual finding", async () =>
        {
            var snapshot = PrioritySnapshot();
            var risk = new RiskEngine().Calculate(snapshot);
            var actions = new RemediationEngine().Plan(snapshot);
            Equal("individual-mfa", risk.RankedFindings[0].Finding.Id, "Fixture needs a different highest individual finding");
            Assert(actions[0].FindingIds.Count == 2 && !actions[0].FindingIds.Contains("individual-mfa"), "Fixture needs a grouped first action.");
            var before = JsonSerializer.Serialize(snapshot);
            using var temp = new TemporaryDirectory();
            foreach (var kind in new[] { ReportKind.Executive, ReportKind.Technical })
            {
                var path = temp.File(kind + ".json");
                await new ReportingEngine().ExportAsync(snapshot, kind, ReportFormat.Json, path);
                using var document = JsonDocument.Parse(await File.ReadAllBytesAsync(path));
                var rows = RemediationRows(document.RootElement);
                Equal(actions[0].Id, rows[0][0].GetString()!, "Report priority differs from grouped remediation engine");
                var narrative = ExecutiveParagraphs(document.RootElement);
                Assert(narrative.Any(p => p.Contains($"The first remediation priority is '{actions[0].Title}' [{actions[0].Id}]", StringComparison.Ordinal)), "Narrative contradicts priority 1 of the structured remediation plan.");
                Assert(narrative.Any(p => p.Contains("highest-risk individual finding is 'Require MFA'", StringComparison.Ordinal)), "Highest individual finding is not distinguished from grouped priorities.");
                Assert(!narrative.Any(p => p.Contains("first remediation priority is 'Require MFA'", StringComparison.Ordinal)), "Individual risk overrides the higher-impact shared-cause action.");
            }
            Equal(before, JsonSerializer.Serialize(snapshot), "Reporting changed collected evidence or dispositions");
        });
        await test.Check("Executive top ten and narrative share deterministic reduction and ID ordering even for unsorted tied actions", async () =>
        {
            var snapshot = new EnvironmentSnapshot { Id = "report-ties", UpdatedAt = CoreTests.FixtureTime };
            snapshot.Assets.Add(new Asset { Id = "tie-asset", BusinessCriticality = 3 });
            for (var i = 0; i < 12; i++)
                snapshot.Findings.Add(new Finding { Id = $"tie-{i:00}", Title = $"Finding {i:00}", Severity = Severity.High,
                    Category = SecurityCategory.Endpoint, AssetIds = ["tie-asset"], Confidence = 1 });
            var planned = new RemediationEngine().Plan(snapshot).ToArray();
            Assert(planned.All(a => a.ModeledRiskReduction == planned[0].ModeledRiskReduction), "Fixture actions must tie.");
            var expected = planned.Select((action, index) => action with { Title = $"Task {planned.Length - index:00}" }).ToArray();
            var engine = new ReportingEngine(new RiskEngine(), new FixtureRemediationEngine(expected.Reverse().ToArray()),
                new ComplianceEngine(), new AttackPathEngine());
            using var temp = new TemporaryDirectory();
            await engine.ExportAsync(snapshot, ReportKind.Executive, ReportFormat.Json, temp.File("ties.json"));
            using var document = JsonDocument.Parse(await File.ReadAllBytesAsync(temp.File("ties.json")));
            var rows = RemediationRows(document.RootElement);
            Equal(10, rows.Length, "Executive plan exceeds or truncates the top-ten limit incorrectly");
            for (var i = 0; i < rows.Length; i++)
            {
                Equal(expected[i].Id, rows[i][0].GetString()!, "Tie order or top-ten selection changed");
                Equal((i + 1).ToString(CultureInfo.InvariantCulture), rows[i][1].GetString()!, "Published priority is not sequential");
            }
            Assert(ExecutiveParagraphs(document.RootElement).Any(p => p.Contains($"'{expected[0].Title}' [{expected[0].Id}]", StringComparison.Ordinal)), "Narrative uses a different tie order from the plan.");
            snapshot.Findings.Reverse();
            Equal(string.Join(";", planned.Select(a => a.Id)), string.Join(";", new RemediationEngine().Plan(snapshot).Select(a => a.Id)), "Input order changes tied remediation priority");
        });
        await test.Check("Remediation reasons and structured reports use the same published midpoint value across cultures", async () =>
        {
            var priorCulture = CultureInfo.CurrentCulture;
            try
            {
                CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("fr-FR");
                using var temp = new TemporaryDirectory();
                // Include values on both sides of a formatting midpoint, and a two-decimal
                // sum susceptible to binary floating-point accumulation at 70.25.
                var cases = new[] { new[] { 70.249 }, new[] { 70.251 }, new[] { 70.349 }, new[] { 70.351 }, new[] { 66.07, 4.14, 0.04 } };
                foreach (var values in cases)
                {
                    var snapshot = new EnvironmentSnapshot { Id = "report-rounding", UpdatedAt = CoreTests.FixtureTime };
                    var scores = new Dictionary<string, double>(StringComparer.Ordinal);
                    for (var i = 0; i < values.Length; i++)
                    {
                        var id = $"round-{i}";
                        snapshot.Findings.Add(new Finding { Id = id, Title = "Review the shared configuration", RootCauseKey = "same-cause",
                            Severity = Severity.High, Category = SecurityCategory.Endpoint, Confidence = 0.875 });
                        scores.Add(id, values[i]);
                    }
                    var risk = new FixtureRiskEngine(scores);
                    var remediation = new RemediationEngine(risk);
                    var action = remediation.Plan(snapshot).Single();
                    Equal(Math.Round(values.OrderDescending().Sum(), 2), action.ModeledRiskReduction, "Published numeric risk precision changed");
                    var published = action.ModeledRiskReduction.ToString("0.0", CultureInfo.InvariantCulture);
                    Assert(action.Why.Contains($"Approximately {published} currently modeled risk points", StringComparison.Ordinal), "Description formats raw rather than published risk, or depends on the operator culture.");
                    await new ReportingEngine(risk, remediation, new ComplianceEngine(), new AttackPathEngine())
                        .ExportAsync(snapshot, ReportKind.Executive, ReportFormat.Json, temp.File("round.json"));
                    using var document = JsonDocument.Parse(await File.ReadAllBytesAsync(temp.File("round.json")));
                    var row = RemediationRows(document.RootElement).Single();
                    Equal(action.Why, row[3].GetString()!, "Structured report replaced the canonical reason");
                    Equal(published + " units", row[7].GetString()!, "Report reduction and business reason disagree");
                    Assert(ExecutiveParagraphs(document.RootElement).Any(p => p.Contains($"direct reduction of {published} currently modeled risk units", StringComparison.Ordinal)), "Executive estimate disagrees with the structured plan.");
                }
            }
            finally { CultureInfo.CurrentCulture = priorCulture; }
        });
        await test.Check("Empty executive reports preserve unknown coverage without inventing remediation", async () =>
        {
            using var temp = new TemporaryDirectory();
            await new ReportingEngine().ExportAsync(new EnvironmentSnapshot { Id = "empty-report", UpdatedAt = CoreTests.FixtureTime },
                ReportKind.Executive, ReportFormat.Json, temp.File("empty.json"));
            using var document = JsonDocument.Parse(await File.ReadAllBytesAsync(temp.File("empty.json")));
            Equal(JsonValueKind.Null, document.RootElement.GetProperty("GlobalSecurityScore").ValueKind, "Unassessed score became a security assurance");
            Equal(0, RemediationRows(document.RootElement).Length, "Empty evidence produced an action");
            var paragraphs = ExecutiveParagraphs(document.RootElement);
            Assert(paragraphs.Any(p => p.Contains("No active scored findings", StringComparison.Ordinal)) &&
                !paragraphs.Any(p => p.Contains("first remediation priority", StringComparison.Ordinal)), "Empty evidence invented an executive priority.");
        });
        await test.Check("Current risk acceptance retains individual risk without inventing an actionable executive priority", async () =>
        {
            var snapshot = PrioritySnapshot();
            snapshot.Findings.RemoveAll(f => f.Id != "individual-mfa");
            snapshot.Findings[0].Status = FindingStatus.AcceptedRisk;
            snapshot.Findings[0].AcceptedUntil = CoreTests.FixtureTime.AddYears(50);
            using var temp = new TemporaryDirectory();
            await new ReportingEngine().ExportAsync(snapshot, ReportKind.Executive, ReportFormat.Json, temp.File("accepted.json"));
            using var document = JsonDocument.Parse(await File.ReadAllBytesAsync(temp.File("accepted.json")));
            Assert(document.RootElement.GetProperty("TotalModeledRisk").GetDouble() > 0, "Acceptance erased modeled risk.");
            Equal(0, RemediationRows(document.RootElement).Length, "Current acceptance became an actionable remediation");
            var paragraphs = ExecutiveParagraphs(document.RootElement);
            Assert(paragraphs.Any(p => p.Contains("No currently actionable remediation group", StringComparison.Ordinal)) &&
                paragraphs.Any(p => p.Contains("highest-risk individual finding is 'Require MFA'", StringComparison.Ordinal)) &&
                !paragraphs.Any(p => p.Contains("first remediation priority", StringComparison.Ordinal)), "Narrative promoted a current acceptance as plan priority 1.");
        });
        await test.Check("Reports escape active HTML and neutralize spreadsheet formulas", async () =>
        {
            using var temp = new TemporaryDirectory(); var snapshot = new DemoLab().Create(CoreTests.FixtureTime);
            snapshot.Name = "<script id=\"qa-injection\">alert(1)</script>";
            snapshot.Assets[0].Name = "=HYPERLINK(\"https://example.invalid\",\"external\")";
            await new ReportingEngine().ExportAsync(snapshot, ReportKind.AssetInventory, ReportFormat.Html, temp.File("report.html"));
            var html = await File.ReadAllTextAsync(temp.File("report.html"));
            Assert(!html.Contains("<script id=\"qa-injection\">") && html.Contains("&lt;script"), "Untrusted metadata became active HTML.");
            await new ReportingEngine().ExportAsync(snapshot, ReportKind.AssetInventory, ReportFormat.Csv, temp.File("report.csv"));
            var csv = await File.ReadAllTextAsync(temp.File("report.csv"));
            Assert(ParseCsv(csv.TrimStart('\uFEFF')).Any(row => row.Any(cell => cell.StartsWith("'=HYPERLINK("))), "Spreadsheet formula was not neutralized.");
        });
        await test.Check("Cancelled reports preserve a prior artifact and leave no partial file", async () =>
        {
            using var temp = new TemporaryDirectory(); var path = temp.File("existing.pdf"); await File.WriteAllTextAsync(path, "previous approved report");
            using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
            await Throws<OperationCanceledException>(() => new ReportingEngine().ExportAsync(demo, ReportKind.Technical, ReportFormat.Pdf, path, cancelled.Token));
            Equal("previous approved report", await File.ReadAllTextAsync(path), "Cancellation damaged the previous artifact");
            Equal(1, Directory.GetFiles(temp.Path).Length, "Cancellation left temporary output");
        });
        await test.Check("Invalid report enums and output destinations fail visibly", async () =>
        {
            using var temp = new TemporaryDirectory(); var engine = new ReportingEngine();
            await Throws<ArgumentOutOfRangeException>(() => engine.ExportAsync(demo, (ReportKind)999, ReportFormat.Json, temp.File("bad.json")));
            await Throws<ArgumentOutOfRangeException>(() => engine.ExportAsync(demo, ReportKind.Executive, (ReportFormat)999, temp.File("bad.json")));
            await Throws<ArgumentException>(() => engine.ExportAsync(demo, ReportKind.Executive, ReportFormat.Json, ""));
            await File.WriteAllTextAsync(temp.File("blocked"), "This is a file.");
            await Throws<IOException>(() => engine.ExportAsync(demo, ReportKind.Executive, ReportFormat.Json, Path.Combine(temp.File("blocked"), "report.json")));
        });
        await test.Check("Local analyst cites collected evidence and distinguishes inference", () =>
        {
            foreach (var question in new[] { "What should we fix first?", "Why did our security score decrease?", "Which assets represent the highest risk?", "Explain finding-log4j", "What changed since the previous assessment?", "Show attack paths" })
            {
                var answer = new EvidenceAnalyst().Answer(demo, question);
                Assert(!answer.UsedAi && !string.IsNullOrWhiteSpace(answer.Answer), "Basic analysis requires AI.");
                Assert(answer.EvidenceIds.All(id => demo.Nodes.Any(n => n.Id == id)), "Analyst fabricated a citation.");
            }
            var explanation = new EvidenceAnalyst().Answer(demo, "Explain finding-log4j");
            Assert(explanation.EvidenceIds.Count > 0 && explanation.Inferences.Count > 0, "Evidence was not distinguished from modeled interpretation.");
        });
        await test.Check("External AI needs evidence authorization and rejects invented citations", async () =>
        {
            var provider = new FixtureAiProvider(); var analyst = new EvidenceGroundedAiAnalyst(provider);
            await Throws<InvalidOperationException>(() => analyst.AnswerAsync(demo, "Explain risk", false));
            Equal(0, provider.Calls, "Evidence disclosed without authorization");
            provider.InventCitation = true;
            await Throws<InvalidDataException>(() => analyst.AnswerAsync(demo, "Explain risk", true));
            provider.InventCitation = false; var before = demo.Nodes[0].Label;
            var result = await analyst.AnswerAsync(demo, "Explain risk", true);
            Equal(before, demo.Nodes[0].Label, "Provider mutated collected evidence");
            Assert(result.UsedAi && result.Inferences.Any(x => x.Contains("unverified AI interpretation")), "Provider interpretation lost its boundary.");
        });
    }

    private static EnvironmentSnapshot PrioritySnapshot()
    {
        var snapshot = new EnvironmentSnapshot { Id = "report-priority", Name = "Synthetic report priority fixture", Mode = EnvironmentMode.Demo,
            CreatedAt = CoreTests.FixtureTime, UpdatedAt = CoreTests.FixtureTime };
        snapshot.Assets.Add(new Asset { Id = "identity-asset", BusinessCriticality = 3 });
        snapshot.Assets.Add(new Asset { Id = "patch-one", BusinessCriticality = 3 });
        snapshot.Assets.Add(new Asset { Id = "patch-two", BusinessCriticality = 3 });
        snapshot.Findings.Add(new Finding { Id = "individual-mfa", Title = "Require MFA", RootCauseKey = "mfa", Severity = Severity.Critical,
            Category = SecurityCategory.Identity, AssetIds = ["identity-asset"], Confidence = 1 });
        foreach (var id in new[] { "patch-one", "patch-two" })
            snapshot.Findings.Add(new Finding { Id = id + "-finding", Title = "Apply the missing security update", RootCauseKey = "shared-patch",
                Severity = Severity.High, Category = SecurityCategory.Endpoint, AssetIds = [id], Confidence = 1 });
        return snapshot;
    }

    private static string[] ExecutiveParagraphs(JsonElement document) => ReportSection(document, "Business risk and recommended focus")
        .GetProperty("Paragraphs").EnumerateArray().Select(p => p.GetString()!).ToArray();

    private static JsonElement[] RemediationRows(JsonElement document) => ReportSection(document, "Prioritized remediation plan")
        .GetProperty("Tables")[0].GetProperty("Rows").EnumerateArray().ToArray();

    private static JsonElement ReportSection(JsonElement document, string title) => document.GetProperty("Sections")
        .EnumerateArray().Single(s => s.GetProperty("Title").GetString() == title);

    private sealed class FixtureRemediationEngine(IReadOnlyList<RemediationAction> actions) : IRemediationEngine
    {
        public IReadOnlyList<RemediationAction> Plan(EnvironmentSnapshot snapshot) => actions;
    }

    private sealed class FixtureRiskEngine(IReadOnlyDictionary<string, double> scores) : IRiskEngine
    {
        public RiskAssessment Calculate(EnvironmentSnapshot snapshot, DateTimeOffset? now = null)
        {
            var findings = snapshot.Findings.Select(f => new ScoredFinding(f, scores[f.Id], ["Synthetic QA numeric input"]))
                .OrderByDescending(f => f.Risk).ThenBy(f => f.Finding.Id, StringComparer.Ordinal).ToArray();
            return new RiskAssessment(50, findings.Sum(f => f.Risk), new Dictionary<SecurityCategory, double> { [SecurityCategory.Endpoint] = 50 },
                findings, now ?? CoreTests.FixtureTime);
        }
    }

    private static void ValidatePdf(byte[] bytes)
    {
        var text = Encoding.Latin1.GetString(bytes);
        Assert(text.StartsWith("%PDF-") && text.TrimEnd().EndsWith("%%EOF"), "Incomplete PDF envelope.");
        var match = Regex.Match(text, @"startxref\s+(\d+)\s+%%EOF\s*$"); Assert(match.Success, "Missing PDF cross-reference pointer.");
        var offset = int.Parse(match.Groups[1].Value); Assert(offset >= 0 && offset < bytes.Length && text.AsSpan(offset).StartsWith("xref"), "PDF cross-reference offset is invalid.");
        var objects = Regex.Matches(text, @"(?m)^(\d+) 0 obj\s"); Assert(objects.Count > 4, "PDF has no page/document objects.");
        Assert(Regex.IsMatch(text, @"/Type\s*/Pages\b") && Regex.IsMatch(text, @"/Type\s*/Page\b") && text.Contains("SENTINEL"), "PDF is missing pages or product context.");
        var xrefLines = text[offset..].Split('\n'); var index = 2;
        while (index < xrefLines.Length && Regex.IsMatch(xrefLines[index], @"^\d{10} \d{5} [nf]"))
        {
            var entry = xrefLines[index];
            if (entry[17] == 'n')
            {
                var objectOffset = int.Parse(entry[..10]);
                Assert(objectOffset >= 0 && objectOffset < bytes.Length && Regex.IsMatch(text[objectOffset..], @"^\d+ 0 obj"), "PDF xref points outside an object.");
            }
            index++;
        }
        Assert(index > 5, "PDF xref entries missing.");
    }

    private static List<List<string>> ParseCsv(string text)
    {
        var rows = new List<List<string>>(); var row = new List<string>(); var cell = new StringBuilder(); var quoted = false;
        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];
            if (c == '"') { if (quoted && i + 1 < text.Length && text[i + 1] == '"') { cell.Append('"'); i++; } else quoted = !quoted; }
            else if (!quoted && c == ',') { row.Add(cell.ToString()); cell.Clear(); }
            else if (!quoted && c is '\r' or '\n')
            {
                if (c == '\r' && i + 1 < text.Length && text[i + 1] == '\n') i++;
                row.Add(cell.ToString()); cell.Clear(); rows.Add(row); row = [];
            }
            else cell.Append(c);
        }
        Assert(!quoted, "CSV quoted field is unterminated.");
        if (cell.Length > 0 || row.Count > 0) { row.Add(cell.ToString()); rows.Add(row); }
        return rows;
    }

    private sealed class FixtureAiProvider : IAiProvider
    {
        public string Name => "Authorized QA provider";
        public int Calls { get; private set; }
        public bool InventCitation { get; set; }
        public Task<AnalystAnswer> AnswerAsync(string question, IReadOnlyList<EvidenceNode> evidence, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested(); Calls++;
            evidence[0].Label = "Provider changed its isolated input";
            return Task.FromResult(new AnalystAnswer("Fixture interpretation", [InventCitation ? "invented-node" : evidence[0].Id], [], true));
        }
    }
}
