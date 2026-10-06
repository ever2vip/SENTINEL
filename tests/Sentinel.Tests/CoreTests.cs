using System.Text.Json;
using Sentinel.Core;
using static Sentinel.Tests.TestRunner;

namespace Sentinel.Tests;

internal static class CoreTests
{
    internal static readonly DateTimeOffset FixtureTime = DateTimeOffset.Parse("2026-10-06T12:00:00Z");
    public static async Task Run(TestRunner test)
    {
        await test.Check("Demo is deterministic and inventory has enterprise scale", () =>
        {
            var first = new DemoLab().Create(FixtureTime);
            Equal(JsonSerializer.Serialize(first), JsonSerializer.Serialize(new DemoLab().Create(FixtureTime)), "Fixed-clock demo differs");
            Equal(250, first.Assets.Count(x => x.Kind == AssetKind.Endpoint), "Endpoint inventory");
            Equal(12, first.Assets.Count(x => x.Kind == AssetKind.Server), "Server inventory");
            Assert(first.Assets.Any(x => x.Kind == AssetKind.NetworkDevice) && first.Assets.Any(x => x.Kind == AssetKind.CloudResource) && first.Assets.Any(x => x.Kind == AssetKind.WebApplication), "Missing inventory domains.");
            Assert(first.Identities.Count >= 200 && first.Certificates.Count >= 5, "Missing identity/certificate fixtures.");
        });
        await test.Check("Demo graph and finding references are complete and unique", () =>
        {
            var demo = new DemoLab().Create(FixtureTime);
            var nodes = demo.Nodes.Select(x => x.Id).ToHashSet();
            var assets = demo.Assets.Select(x => x.Id).ToHashSet();
            Equal(demo.Nodes.Count, nodes.Count, "Duplicate node identifiers");
            Equal(demo.Edges.Count, demo.Edges.Select(x => x.Id).Distinct().Count(), "Duplicate edge identifiers");
            Assert(demo.Edges.All(x => nodes.Contains(x.SourceId) && nodes.Contains(x.TargetId)), "Dangling graph edge.");
            Assert(demo.Findings.All(x => x.AssetIds.All(assets.Contains) && x.EvidenceIds.All(nodes.Contains) && x.ControlIds.All(nodes.Contains)), "Dangling finding reference.");
        });
        await test.Check("Demo provenance and history remain explicitly synthetic", () =>
        {
            var demo = new DemoLab().Create(FixtureTime);
            Assert(demo.Nodes.All(x => x.Source == DemoLab.Source) && demo.Findings.All(x => x.Source == DemoLab.Source) && demo.Observations.All(x => x.Source == DemoLab.Source) && demo.Changes.All(x => x.Source == DemoLab.Source), "Synthetic provenance absent.");
            Assert(demo.Assets.All(x => x.Properties.GetValueOrDefault("synthetic") == "true"), "Asset lacks synthetic marker.");
            Assert(demo.Scans.All(x => x.Message.Contains("not a real scan")), "Scenario history appears to be live scans.");
            var score = new RiskEngine().Calculate(demo, FixtureTime);
            Equal(score.GlobalScore, demo.ScoreHistory[^1].Score, "Current history bypasses risk engine");
            Assert(demo.ScoreHistory.Zip(demo.ScoreHistory.Skip(1)).All(x => x.First.At < x.Second.At), "History dates are unordered.");
        });
        await test.Check("Unknown posture is distinct from a clean completed assessment", () =>
        {
            var engine = new RiskEngine();
            var empty = engine.Calculate(new EnvironmentSnapshot(), FixtureTime);
            Equal(0, empty.CategoryScores.Count, "Unknown categories reported healthy");
            var clean = new EnvironmentSnapshot { Observations = [new Observation { EngineId = "endpoint", Property = "CategoryCoverage", Value = "assessed" }] };
            var result = engine.Calculate(clean, FixtureTime);
            Assert(result.CategoryScores.ContainsKey(SecurityCategory.Endpoint) && !result.CategoryScores.ContainsKey(SecurityCategory.Cloud), "Coverage was fabricated.");
            Equal(100.0, result.CategoryScores[SecurityCategory.Endpoint], "Clean endpoint assessment");
        });
        await test.Check("Completed collectors with unknown measurements do not report perfect security", () =>
        {
            var snapshot = new EnvironmentSnapshot
            {
                Observations =
                [
                    new Observation { EngineId = "email", Property = "DMARC", Value = "Unknown — resolver timed out" },
                    new Observation { EngineId = "network", Property = "Public exposure", Value = "Unknown — TCP does not establish Internet exposure" },
                    new Observation { EngineId = "web", Property = "Collection method", Value = "HEAD only" },
                    new Observation { EngineId = "endpoint", Property = "AssessmentComplete", Value = "true" }
                ],
                Scans = [new ScanRun { EngineId = "email", Status = ScanStatus.Completed }, new ScanRun { EngineId = "web", Status = ScanStatus.Completed }]
            };
            var result = new RiskEngine().Calculate(snapshot, FixtureTime);
            Equal(0, result.CategoryScores.Count, "All-unknown or bookkeeping observations fabricated assessed categories");
            Equal(0.0, result.GlobalScore, "Unassessed workspace reported a perfect score");
        });
        await test.Check("Business context changes priority beyond identical CVSS", () =>
        {
            var snapshot = new EnvironmentSnapshot
            {
                Assets = [new Asset { Id = "isolated", BusinessCriticality = 1, Exposure = 0 }, new Asset { Id = "critical", BusinessCriticality = 5, Exposure = 1 }],
                Findings = [Finding("isolated-risk", "isolated"), Finding("critical-risk", "critical")]
            };
            var ranks = new RiskEngine().Calculate(snapshot).RankedFindings;
            Equal("critical-risk", ranks[0].Finding.Id, "Context did not prioritize the exposed critical asset");
            Assert(ranks[0].Risk > ranks[1].Risk, "Identical CVSS erased context.");
        });
        await test.Check("Confidence and compensating controls reduce modeled risk", () =>
        {
            var snapshot = new EnvironmentSnapshot { Assets = [new Asset { Id = "asset", BusinessCriticality = 5, Exposure = 1 }], Findings = [Finding("risk", "asset")] };
            var engine = new RiskEngine();
            var original = engine.Calculate(snapshot).TotalRisk;
            snapshot.Findings[0].Confidence = 0.5;
            Assert(engine.Calculate(snapshot).TotalRisk < original, "Uncertain evidence increased certainty.");
            snapshot.Findings[0].Confidence = 1; snapshot.Findings[0].CompensatingControl = 1;
            Assert(engine.Calculate(snapshot).TotalRisk < original && engine.Calculate(snapshot).TotalRisk > 0, "Control erased risk or did not reduce it.");
        });
        await test.Check("Accepted risk remains modeled; fixed and false positive are excluded", () =>
        {
            var demo = new DemoLab().Create(FixtureTime);
            var ranked = new RiskEngine().Calculate(demo, FixtureTime).RankedFindings;
            Assert(ranked.Any(x => x.Finding.Status == FindingStatus.AcceptedRisk && x.Risk > 0), "Risk acceptance erased modeled risk.");
            Assert(ranked.All(x => x.Finding.Status is not (FindingStatus.Fixed or FindingStatus.FalsePositive)), "Closed/invalid findings contribute risk.");
        });
        await test.Check("Untrusted numeric scoring metadata remains finite and bounded", () =>
        {
            var demo = new DemoLab().Create(FixtureTime);
            foreach (var finding in demo.Findings) { finding.Cvss = double.PositiveInfinity; finding.Confidence = double.NaN; finding.Exploitability = -100; finding.IdentityReach = double.PositiveInfinity; }
            var risk = new RiskEngine().Calculate(demo, FixtureTime);
            Assert(double.IsFinite(risk.TotalRisk) && risk.GlobalScore is >= 0 and <= 100 && risk.RankedFindings.All(x => x.Risk is >= 0 and <= 100), "Nonfinite metadata leaked into risk scores.");
        });
        await test.Check("Attack paths are supported chains to critical assets with defensive breakpoints", () =>
        {
            var demo = new DemoLab().Create(FixtureTime);
            var paths = new AttackPathEngine().Analyze(demo);
            Assert(paths.Count >= 5, "Missing defensive path fixtures.");
            Assert(paths.All(x => demo.Assets.Any(a => a.Id == x.CriticalAssetId && a.IsCritical) && x.NodeIds[0] == "internet" && x.EdgeIds.Count == x.NodeIds.Count - 1 && x.Confidence is >= 0 and <= 1 && !string.IsNullOrWhiteSpace(x.RecommendedAction)), "Invalid defensive path.");
            Assert(paths.Any(x => x.NodeIds.Contains("service-identity-01") && x.CriticalAssetId == "server-file01"), "Identity relationship was not preserved in downstream path.");
        });
        await test.Check("Fixed, false-positive, or unknown prerequisites interrupt paths", () =>
        {
            foreach (var state in new[] { FindingStatus.Fixed, FindingStatus.FalsePositive })
            {
                var demo = new DemoLab().Create(FixtureTime);
                demo.Findings.Single(x => x.Id == "finding-log4j").Status = state;
                Assert(!new AttackPathEngine().Analyze(demo).Any(x => x.FindingIds.Contains("finding-log4j")), "Inactive finding still enables a path.");
            }
            var missing = new DemoLab().Create(FixtureTime); missing.Findings.RemoveAll(x => x.Id == "finding-log4j");
            Assert(!new AttackPathEngine().Analyze(missing).Any(x => x.NodeIds.Contains("service-erp")), "Missing prerequisite inferred as known.");
        });
        await test.Check("Graph traversal caps branches, depth, and cycles", () =>
        {
            var snapshot = new EnvironmentSnapshot { Nodes = [new EvidenceNode { Id = "internet", Kind = EvidenceKind.Internet }] };
            for (var i = 0; i < 250; i++)
            {
                snapshot.Assets.Add(new Asset { Id = $"asset-{i}", BusinessCriticality = 5 });
                snapshot.Nodes.Add(new EvidenceNode { Id = $"asset-{i}", Kind = EvidenceKind.Asset });
                snapshot.Edges.Add(new EvidenceEdge { Id = $"edge-{i}", SourceId = "internet", TargetId = $"asset-{i}", EnablesPath = true });
                snapshot.Edges.Add(new EvidenceEdge { Id = $"cycle-{i}", SourceId = $"asset-{i}", TargetId = "internet", EnablesPath = true });
            }
            Equal(AttackPathEngine.MaximumPaths, new AttackPathEngine().Analyze(snapshot).Count, "Path cap or cycle handling");
            snapshot.Edges.Clear();
            for (var i = 1; i <= 9; i++)
            {
                snapshot.Nodes.Add(new EvidenceNode { Id = $"chain-{i}", Kind = EvidenceKind.Service });
                snapshot.Edges.Add(new EvidenceEdge { Id = $"chain-edge-{i}", SourceId = i == 1 ? "internet" : $"chain-{i - 1}", TargetId = $"chain-{i}", EnablesPath = true });
            }
            snapshot.Edges.Add(new EvidenceEdge { Id = "beyond-depth", SourceId = "chain-9", TargetId = "asset-0", EnablesPath = true });
            Equal(0, new AttackPathEngine().Analyze(snapshot).Count, "Depth bound");
        });
        await test.Check("Remediation groups root causes without double-counting direct risk", () =>
        {
            var demo = new DemoLab().Create(FixtureTime);
            var risk = new RiskEngine().Calculate(demo, FixtureTime);
            var actions = new RemediationEngine().Plan(demo);
            Assert(actions.Any(x => x.FindingIds.Count > 1), "Duplicate root causes did not group.");
            Equal(actions.Sum(x => x.FindingIds.Count), actions.SelectMany(x => x.FindingIds).Distinct().Count(), "Finding included in multiple actions");
            Assert(actions.Sum(x => x.ModeledRiskReduction) <= risk.TotalRisk + 0.01, "Action estimates double-count modeled risk.");
            Assert(actions.All(x => x.Confidence is >= 0 and <= 1 && x.EvidenceIds.Count > 0 && !string.IsNullOrWhiteSpace(x.Verification)), "Action lacks support or verification.");
        });
        await test.Check("Acceptance expiry returns work to remediation without suppressing score", () =>
        {
            var demo = new DemoLab().Create(FixtureTime);
            var accepted = demo.Findings.Single(x => x.Status == FindingStatus.AcceptedRisk);
            var engine = new RemediationEngine();
            Assert(!engine.Plan(demo).Any(x => x.FindingIds.Contains(accepted.Id)), "Current acceptance not suppressed.");
            var before = new RiskEngine().Calculate(demo, FixtureTime).TotalRisk;
            accepted.AcceptedUntil = FixtureTime.AddDays(-1);
            Assert(engine.Plan(demo).Any(x => x.FindingIds.Contains(accepted.Id)), "Expired acceptance not actionable.");
            Equal(before, new RiskEngine().Calculate(demo, FixtureTime).TotalRisk, "Expiry changed real modeled exposure");
        });
        await test.Check("Compliance maps multiple frameworks without asserting certification", () =>
        {
            var demo = new DemoLab().Create(FixtureTime);
            var results = new ComplianceEngine().Assess(demo);
            Assert(results.Any(x => x.Control.Framework == "NIST CSF 2.0") && results.Any(x => x.Control.Framework == "CIS Controls v8.1"), "Missing framework mappings.");
            Assert(results.Any(x => x.Status == "Observed gap") && results.Any(x => x.Status == "Not assessed"), "Coverage boundaries hidden.");
            Assert(results.All(x => !x.Status.Contains("compliant", StringComparison.OrdinalIgnoreCase) && !x.Status.Contains("certified", StringComparison.OrdinalIgnoreCase)), "Unjustified compliance claim.");
            Assert(results.SelectMany(x => x.FindingIds).All(id => demo.Findings.Any(x => x.Id == id && x.Status is FindingStatus.Open or FindingStatus.AcceptedRisk)), "Invalid compliance finding disposition.");
        });
    }

    private static Finding Finding(string id, string assetId) => new()
    { Id = id, Title = "Authorized test finding", Severity = Severity.High, Category = SecurityCategory.Vulnerability, Cvss = 7.5, AssetIds = [assetId], Confidence = 1 };
}
