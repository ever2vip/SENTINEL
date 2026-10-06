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
