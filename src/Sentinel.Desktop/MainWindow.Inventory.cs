using System.Collections;
using System.Globalization;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Data;
using Sentinel.Core;

namespace Sentinel.Desktop;

public partial class MainWindow
{
    private void RenderAssets(IEnumerable<Asset> assets)
    {
        var list = assets.ToList();
        var byAsset = _coordinator.Risk.RankedFindings.SelectMany(f => f.Finding.AssetIds.Distinct().Select(id => (id, scored: f)))
            .GroupBy(x => x.id).ToDictionary(g => g.Key, g => g.Select(x => x.scored).ToList());
        var observed = Snapshot.Observations.GroupBy(o => o.AssetId).ToDictionary(g => g.Key, g => (DateTimeOffset?)g.Max(o => o.ObservedAt));
        var rows = list.Select(a => new AssetInventoryRow(a, byAsset.GetValueOrDefault(a.Id) ?? [], observed.GetValueOrDefault(a.Id))).OrderByDescending(a => a.PeakRisk).ThenBy(a => a.Name).ToList();
        var search = Ui.Search("Search assets", 300);
        var type = InventoryFilter("Asset type", Enum.GetNames<AssetKind>());
        var os = InventoryFilter("Operating system", list.Select(a => a.OperatingSystem));
        var criticality = InventoryFilter("Criticality", ["Critical · 5/5", "Important · 4/5", "Standard · 3/5", "Supporting · 2/5", "Low · 1/5"]);
        var owner = InventoryFilter("Owner", list.Select(a => a.Owner));
        var risk = InventoryFilter("Risk level", ["Critical", "High", "Medium", "Low", "Not modeled"]);
        var status = InventoryFilter("Status", rows.Select(a => a.Status));
        var count = Ui.Text("", 12, "MutedBrush");
        var grid = InventoryTable(rows, ("Asset", "Name", 0), ("Status", "Status", 130), ("Type", "Kind", 135), ("IP / address", "Address", 175), ("Operating system", "OperatingSystem", 190), ("Owner", "Owner", 150), ("Criticality", "Criticality", 145), ("Peak finding risk", "RiskDisplay", 140), ("Findings", "FindingCount", 95), ("Last observed", "LastAssessed", 165));
        InventoryBadgeColumn(grid, "Status", "Status", "StatusBrush");
        InventoryBadgeColumn(grid, "Criticality", "Criticality", "CriticalityBrush", "CriticalityDetail");
        InventoryBadgeColumn(grid, "Peak finding risk", "RiskDisplay", "RiskBrush", "RiskExplanation");
        InventorySortColumn(grid, "Criticality", "Asset.BusinessCriticality");
        InventorySortColumn(grid, "Peak finding risk", "PeakRisk");
        InventorySortColumn(grid, "Last observed", "LastObservation");
        InventoryAdaptiveColumns(grid, "Owner", "Operating system", "Last observed", "Type");
        var detail = new StackPanel();
        void Filter()
        {
            var filtered = rows.Where(a => MatchesInventoryFilter(type, a.Kind) && MatchesInventoryFilter(os, a.OperatingSystem) &&
                MatchesInventoryFilter(criticality, a.Criticality) && MatchesInventoryFilter(owner, a.Owner) && MatchesInventoryFilter(risk, a.RiskLevel) &&
                MatchesInventoryFilter(status, a.Status) && $"{a.Name} {a.Address} {a.OperatingSystem} {a.Owner} {a.Asset.Environment}".Contains(search.Text.Trim(), StringComparison.OrdinalIgnoreCase)).ToList();
            grid.ItemsSource = filtered;
            count.Text = $"{filtered.Count:N0} of {rows.Count:N0} assets · risk is the highest active linked finding, not a breach probability";
            detail.Children.Clear();
            if (filtered.Count == 0) detail.Children.Add(Ui.Empty("No matching assets", "Adjust the filters or collect evidence from an authorized scope.", "Assets"));
        }
        search.TextChanged += (_, _) => Filter();
        foreach (var filter in new[] { type, os, criticality, owner, risk, status }) filter.SelectionChanged += (_, _) => Filter();
        grid.SelectionChanged += (_, _) =>
        {
            detail.Children.Clear();
            if (grid.SelectedItem is not AssetInventoryRow row) return;
            detail.Children.Add(AssetDetail(row.Asset));
            _ = Dispatcher.InvokeAsync(() => detail.BringIntoView(), System.Windows.Threading.DispatcherPriority.Loaded);
        };
        PageContent.Children.Add(Ui.Card(Ui.Stack(Ui.Section("Asset inventory", "Search and prioritize recorded assets, then inspect the evidence behind their posture."), Ui.Toolbar(search, type, os, criticality, owner, risk, status), count, grid)));
        PageContent.Children.Add(detail);
        Filter();
        if (list.Count == 0) AddEmpty("No assets collected", "Run a supported authorized assessment or import evidence. An inventory record alone does not establish assessment coverage.");
    }

    private Border AssetDetail(Asset asset)
    {
        var linked = Snapshot.Findings.Where(f => f.AssetIds.Contains(asset.Id)).ToList();
        var ranked = _coordinator.Risk.RankedFindings.Where(f => f.Finding.AssetIds.Contains(asset.Id)).ToList();
        var assetNodes = AssetNodeIds(asset);
        var paths = _coordinator.AttackPaths.Where(p => p.NodeIds.Any(assetNodes.Contains) || p.CriticalAssetId == asset.Id).ToList();
        var peak = ranked.Count == 0 ? (double?)null : ranked.Max(f => f.Risk);
        var header = Ui.Stack(Ui.Section(asset.Name, $"{asset.OperatingSystem} · {asset.Owner} · {asset.Environment}"),
            Ui.Toolbar(Ui.Badge(CriticalityLabel(asset.BusinessCriticality), asset.IsCritical ? "HighBrush" : "MutedBrush"), Ui.Badge(AssetStatus(asset)), Ui.Badge($"Recorded exposure factor {asset.Exposure:P0}", asset.Exposure >= .7 ? "HighBrush" : "MutedBrush")),
            Ui.Text($"Highest linked finding risk: {(peak is null ? "Not modeled" : $"{peak:0.0} / 100")} · {linked.Count(f => (f.Status is FindingStatus.Open or FindingStatus.AcceptedRisk) && f.Severity == Severity.Critical)} active critical findings · {paths.Count} defensive paths", 14),
            Ui.Text($"Last observed {asset.LastSeen.LocalDateTime:g} · First recorded {asset.FirstSeen.LocalDateTime:g}", 12, "MutedBrush"));
        header.Children.Add(InventoryTabs(
            ("Overview", () => AssetOverview(asset)),
            ("Software", () => AssetSoftware(asset, linked)),
            ("Services", () => AssetServices(asset)),
            ("Vulnerabilities", () => InventoryFindingLinks(linked)),
            ("Identity access", () => AssetIdentityAccess(asset)),
            ("Exposure", () => AssetExposure(asset, paths)),
            ("Evidence", () => AssetEvidence(asset, linked)),
            ("History", () => InventoryHistory(new[] { asset.Id }.Concat(linked.Select(f => f.Id)).Concat(Snapshot.Certificates.Where(c => c.AssetId == asset.Id).Select(c => c.Id)), asset.FirstSeen, asset.LastSeen)),
            ("Remediation", () => AssetRemediation(asset))));
        return Ui.Card(header);
    }

    private UIElement AssetOverview(Asset asset)
    {
        var body = Ui.Stack(Ui.Section("Business context", "Ownership and importance inform the existing contextual risk engine."));
        body.Children.Add(InventoryTable(asset.Properties.OrderBy(p => p.Key).Select(p => new { Property = p.Key, Value = p.Value }).ToList(), ("Property", "Property", 220), ("Recorded value", "Value", 0)));
        var owner = Ui.Input(asset.Owner); AutomationProperties.SetName(owner, "Asset owner");
        var criticality = Ui.Select(Enumerable.Range(1, 5), asset.BusinessCriticality); AutomationProperties.SetName(criticality, "Business criticality 1 to 5");
        var reason = Ui.Input(); AutomationProperties.SetName(reason, "Reason for business context change");
        var retired = new CheckBox { Content = "Operator-retired · retain unresolved security evidence", IsChecked = asset.Properties.GetValueOrDefault("lifecycle") == "Operator retired" };
        body.Children.Add(Ui.Text("Owner", 12, "MutedBrush")); body.Children.Add(owner);
        body.Children.Add(Ui.Toolbar(Ui.Text("Business criticality · 1–5", 13), criticality));
        body.Children.Add(Ui.Text("Reason for business context change · required", 12, "MutedBrush")); body.Children.Add(reason); body.Children.Add(retired);
        body.Children.Add(Ui.Button("Save business context", () => _ = GuardAsync(async () =>
        {
            await _coordinator.UpdateAssetAsync(asset.Id, owner.Text, (int)criticality.SelectedItem, reason.Text, retired.IsChecked == true);
            OpenAsset(asset.Id);
            ShowNotice("Asset context saved", "The change was audited and contextual risk recalculated. Retirement does not verify remediation.");
        }), true));
        return body;
    }

    private UIElement AssetSoftware(Asset asset, IReadOnlyList<Finding> findings)
    {
        var components = AssetDirectNodes(asset).Where(n => n.Kind == EvidenceKind.Software).Select(n => new { Name = n.Label, Version = n.Properties.GetValueOrDefault("version", "Not recorded"), Source = n.Source, Confidence = n.Confidence.ToString("P0"), Evidence = "Graph inventory", Observed = n.ObservedAt.LocalDateTime.ToString("g") }).ToList();
        components.AddRange(findings.Where(f => !string.IsNullOrWhiteSpace(f.Software)).Select(f => new { Name = f.Software, Version = string.IsNullOrWhiteSpace(f.Version) ? "Not recorded" : f.Version, Source = f.Source, Confidence = f.Confidence.ToString("P0"), Evidence = "Reported by finding", Observed = f.LastSeen.LocalDateTime.ToString("g") }));
        var body = Ui.Stack(Ui.Section("Software evidence", "Finding-reported component versions are partial evidence, not a complete installed application inventory."));
        if (components.Count == 0) body.Children.Add(Ui.Empty("Software inventory unavailable", "No software nodes or component versions have been recorded for this asset.", "Software"));
        else body.Children.Add(InventoryTable(components.Distinct().ToList(), ("Component", "Name", 0), ("Version", "Version", 140), ("Evidence", "Evidence", 165), ("Source", "Source", 150), ("Confidence", "Confidence", 100), ("Observed", "Observed", 165)));
        return body;
    }

    private UIElement AssetServices(Asset asset)
    {
        var services = AssetDirectNodes(asset).Where(n => n.Kind == EvidenceKind.Service).ToList();
        var body = Ui.Stack(Ui.Section("Recorded services", "TCP reachability alone does not establish service identity or Internet exposure. Recorded graph evidence can persist between assessments."));
        if (services.Count == 0) body.Children.Add(Ui.Empty("No service evidence", "No directly related service nodes are recorded. This does not mean that no services are running.", "Service"));
        else
        {
            var table = InventoryTable(services.Select(n => new { Node = n, Name = n.Label, Protocol = n.Properties.GetValueOrDefault("protocolIdentity", n.Properties.GetValueOrDefault("protocol", "Not verified")), Source = n.Source, Confidence = n.Confidence.ToString("P0"), Observed = n.ObservedAt.LocalDateTime.ToString("g") }).ToList(), ("Service", "Name", 0), ("Identity", "Protocol", 160), ("Source", "Source", 145), ("Confidence", "Confidence", 100), ("Observed", "Observed", 165));
            body.Children.Add(table);
            body.Children.Add(Ui.Button("Inspect service relationships", () => OpenEvidence(asset.Id)));
        }
        var observations = Snapshot.Observations.Where(o => o.AssetId == asset.Id && (o.EngineId.Contains("network", StringComparison.OrdinalIgnoreCase) || o.Property.Contains("port", StringComparison.OrdinalIgnoreCase))).OrderByDescending(o => o.ObservedAt).ToList();
        if (observations.Count > 0) body.Children.Add(InventoryObservationTable(observations));
        return body;
    }

    private UIElement AssetIdentityAccess(Asset asset)
    {
        var roots = AssetNodeIds(asset);
        var direct = Snapshot.Edges.Where(e => roots.Contains(e.SourceId) || roots.Contains(e.TargetId)).ToList();
        var related = direct.Select(e => roots.Contains(e.SourceId) ? e.TargetId : e.SourceId).ToHashSet();
        var permissions = Snapshot.Nodes.Where(n => related.Contains(n.Id) && n.Kind == EvidenceKind.Permission).Select(n => n.Id).ToHashSet();
        var permissionEdges = Snapshot.Edges.Where(e => permissions.Contains(e.TargetId) || permissions.Contains(e.SourceId)).ToList();
        var identityIds = Snapshot.Nodes.Where(n => n.Kind == EvidenceKind.Identity && (related.Contains(n.Id) || permissionEdges.Any(e => e.SourceId == n.Id || e.TargetId == n.Id))).Select(n => n.Id).ToHashSet();
        var body = Ui.Stack(Ui.Section("Identity and permission relationships", "Only explicit asset relationships and identity–permission–asset chains are shown. Group evidence is distinct from a collected user record."));
        if (identityIds.Count == 0 && permissions.Count == 0) body.Children.Add(Ui.Empty("Access relationships not recorded", "Collect authorized identity or permission evidence to establish who can access this asset.", "Identity"));
        foreach (var node in Snapshot.Nodes.Where(n => identityIds.Contains(n.Id) || permissions.Contains(n.Id)))
        {
            var identity = Snapshot.Identities.FirstOrDefault(i => i.Id == node.Id);
            body.Children.Add(Ui.Card(Ui.Stack(Ui.Toolbar(Ui.Badge(node.Kind.ToString(), "InfoBrush"), Ui.Text(node.Label, 16, bold: true)),
                Ui.Text(identity is null ? "Graph or group evidence · full identity posture unavailable" : $"{identity.PrincipalName} · MFA: {(identity.MfaEnabled is null ? "Unknown" : identity.MfaEnabled.Value ? "Enabled" : "Not enabled")}", 13),
                Ui.Text($"{node.Source} · Confidence {node.Confidence:P0} · Observed {node.ObservedAt.LocalDateTime:g}", 12, "MutedBrush"), Ui.Button("Inspect access evidence", () => OpenEvidence(node.Id))), 16));
        }
        return body;
    }

    private UIElement AssetExposure(Asset asset, IReadOnlyList<AttackPath> paths)
    {
        var body = Ui.Stack(Ui.Section("Recorded network exposure", "Exposure is a contextual model factor. A missing or zero factor does not prove that a resource is private."), Ui.Badge($"Exposure factor {asset.Exposure:P0}", asset.Exposure >= .7 ? "HighBrush" : "MutedBrush"));
        var roots = AssetNodeIds(asset);
        var nodes = Snapshot.Nodes.ToDictionary(n => n.Id);
        var direct = Snapshot.Edges.Where(e => (roots.Contains(e.SourceId) || roots.Contains(e.TargetId)) &&
            (nodes.GetValueOrDefault(roots.Contains(e.SourceId) ? e.TargetId : e.SourceId)?.Kind is EvidenceKind.Service or EvidenceKind.IP or EvidenceKind.Domain or EvidenceKind.Internet)).ToList();
        var related = direct.Select(e => roots.Contains(e.SourceId) ? e.TargetId : e.SourceId).ToHashSet();
        var edges = direct.Concat(Snapshot.Edges.Where(e => (related.Contains(e.TargetId) && nodes.GetValueOrDefault(e.SourceId)?.Kind == EvidenceKind.Internet) ||
            (related.Contains(e.SourceId) && nodes.GetValueOrDefault(e.TargetId)?.Kind == EvidenceKind.Internet))).DistinctBy(e => e.Id).ToList();
        body.Children.Add(InventoryRelationshipTable(edges));
        body.Children.Add(Ui.Text($"{paths.Count} modeled defensive paths include this asset. Paths describe evidence and permissions; SENTINEL never executes them.", 13, "MutedBrush"));
        if (paths.Count > 0) body.Children.Add(Ui.Button("Review defensive attack paths", () => Navigate("Attack Paths"), true));
        return body;
    }

    private UIElement AssetEvidence(Asset asset, IReadOnlyList<Finding> findings)
    {
        var body = Ui.Stack(Ui.Section("Evidence and provenance", "Engine observations, explicit graph relationships and linked finding evidence retain their source and timestamps."));
        var observations = Snapshot.Observations.Where(o => o.AssetId == asset.Id).OrderByDescending(o => o.ObservedAt).ToList();
        if (observations.Count > 0) body.Children.Add(InventoryObservationTable(observations));
        else body.Children.Add(Ui.Text("No engine observations recorded for this asset.", 13, "MutedBrush"));
        var ids = AssetNodeIds(asset).Concat(AssetDirectNodes(asset).Select(n => n.Id)).Concat(findings.SelectMany(f => f.EvidenceIds)).ToHashSet();
        body.Children.Add(InventoryEvidenceNodes(Snapshot.Nodes.Where(n => ids.Contains(n.Id)).ToList()));
        var certs = Snapshot.Certificates.Where(c => c.AssetId == asset.Id).ToList();
        if (certs.Count > 0) body.Children.Add(InventoryTable(certs.Select(c => new { c.Subject, c.Issuer, Expires = c.NotAfter.LocalDateTime.ToString("g"), c.Thumbprint }).ToList(), ("Certificate", "Subject", 0), ("Issuer", "Issuer", 200), ("Expires", "Expires", 165), ("Thumbprint", "Thumbprint", 230)));
        body.Children.Add(Ui.Button("Focus asset in evidence graph", () => OpenEvidence(asset.Id), true));
        return body;
    }

    private UIElement AssetRemediation(Asset asset)
    {
        var actions = _coordinator.Remediations.Where(a => a.AssetIds.Contains(asset.Id)).ToList();
        var body = Ui.Stack(Ui.Section("Prioritized remediation", "Estimated modeled risk reduction is not a verified outcome. Recollect evidence to verify the fix."));
        if (actions.Count == 0) body.Children.Add(Ui.Empty("No modeled remediation actions", "No active source findings produced a remediation action for this asset. Coverage can still be incomplete.", "Remediation"));
        foreach (var action in actions)
            body.Children.Add(Ui.Card(Ui.Stack(Ui.Text(action.Title, 16, bold: true), Ui.Text(action.Why), Ui.Text($"{action.FindingIds.Count} linked findings · {action.ModeledRiskReduction:0.0} modeled risk units · Confidence {action.Confidence:P0}", 12, "MutedBrush"), Ui.Text(action.Instructions), Ui.Text("Verify: " + action.Verification, 13), Ui.Button("Open remediation workspace", () => Navigate("Remediation"))), 16));
        return body;
    }

    private void RenderFindings(IEnumerable<Finding> findings)
    {
        var list = findings.ToList();
        var scored = _coordinator.Risk.RankedFindings.ToDictionary(f => f.Finding.Id);
        var assets = Snapshot.Assets.ToDictionary(a => a.Id);
        var rows = list.Select(f => new FindingRow(f, scored.GetValueOrDefault(f.Id)?.Risk, f.AssetIds.Where(assets.ContainsKey).Select(id => assets[id]).ToList(), f.Status == FindingStatus.Open && GetFindingReview(f.Id))).ToList();
        var search = Ui.Search("Search findings", 300);
        var severity = InventoryFilter("Severity", Enum.GetNames<Severity>().Reverse());
        var state = InventoryFilter("State", ["Open", "Under Review", "Remediated", "Accepted Risk", "False Positive"]);
        var asset = InventoryFilter("Asset", list.SelectMany(f => f.AssetIds).Where(assets.ContainsKey).Select(id => assets[id].Name));
        var exposure = InventoryFilter("Exposure", ["High exposure factor", "Recorded exposure", "No factor recorded"]);
        var confidence = InventoryFilter("Confidence", ["90–100%", "70–89%", "Below 70%"]);
        var cve = InventoryFilter("CVE", ["Has CVE", "No CVE recorded"]);
        var sort = Ui.Select(new[] { "Contextual risk", "Severity", "Last seen", "Title" }, "Contextual risk"); AutomationProperties.SetName(sort, "Sort findings");
        var grid = InventoryTable(rows, ("Finding", "Title", 0), ("Severity", "Severity", 125), ("Contextual risk", "RiskDisplay", 145), ("CVE", "Cve", 145), ("Assets", "AssetCount", 90), ("Exposure", "Exposure", 155), ("State", "Status", 145), ("Confidence", "Confidence", 105), ("Last seen", "LastSeen", 165));
        InventoryBadgeColumn(grid, "Severity", "Severity", "SeverityBrush");
        InventoryBadgeColumn(grid, "Contextual risk", "RiskDisplay", "RiskBrush", "RiskExplanation");
        InventoryBadgeColumn(grid, "State", "Status", "StatusBrush");
        InventorySortColumn(grid, "Severity", "Finding.Severity");
        InventorySortColumn(grid, "Contextual risk", "Risk");
        InventorySortColumn(grid, "Confidence", "Finding.Confidence");
        InventorySortColumn(grid, "Last seen", "Finding.LastSeen");
        InventoryAdaptiveColumns(grid, "Last seen", "Exposure", "Confidence", "CVE");
        var count = Ui.Text("", 12, "MutedBrush");
        var details = new StackPanel();
        void Filter()
        {
            IEnumerable<FindingRow> filtered = rows.Where(r => MatchesInventoryFilter(severity, r.Severity) && MatchesInventoryFilter(state, r.Status) &&
                (asset.SelectedIndex == 0 || r.Assets.Any(a => a.Name == asset.SelectedItem?.ToString())) && MatchesInventoryFilter(exposure, r.Exposure) &&
                MatchesInventoryFilter(confidence, r.ConfidenceBand) && (cve.SelectedIndex == 0 || (cve.SelectedItem?.ToString() == "Has CVE") == !string.IsNullOrWhiteSpace(r.Finding.Cve)) &&
                $"{r.Title} {r.Finding.Description} {r.Cve} {r.Finding.Software} {r.Finding.Source} {string.Join(' ', r.Assets.Select(a => a.Name))}".Contains(search.Text.Trim(), StringComparison.OrdinalIgnoreCase));
            filtered = sort.SelectedItem?.ToString() switch { "Severity" => filtered.OrderByDescending(r => r.Finding.Severity).ThenByDescending(r => r.Risk), "Last seen" => filtered.OrderByDescending(r => r.Finding.LastSeen), "Title" => filtered.OrderBy(r => r.Title), _ => filtered.OrderByDescending(r => r.Risk) };
            var matching = filtered.ToList(); grid.ItemsSource = matching;
            count.Text = $"{matching.Count:N0} of {rows.Count:N0} findings · accepted risk remains modeled · under review remains open";
            details.Children.Clear();
            if (matching.Count == 0) details.Children.Add(Ui.Empty("No matching findings", "Adjust filters. Missing findings do not establish complete or healthy assessment coverage.", "Vulnerabilities"));
        }
        search.TextChanged += (_, _) => Filter();
        foreach (var filter in new[] { severity, state, asset, exposure, confidence, cve, sort }) filter.SelectionChanged += (_, _) => Filter();
        grid.SelectionChanged += (_, _) =>
        {
            details.Children.Clear();
            if (grid.SelectedItem is not FindingRow row) return;
            details.Children.Add(FindingDetail(row.Finding));
            _ = Dispatcher.InvokeAsync(() => details.BringIntoView(), System.Windows.Threading.DispatcherPriority.Loaded);
        };
        PageContent.Children.Add(Ui.Card(Ui.Stack(Ui.Section("Finding management", "Prioritize business impact using contextual risk, then inspect source evidence and defensive verification."), Ui.Toolbar(search, severity, state, asset, exposure, confidence, cve, sort), count, grid)));
        PageContent.Children.Add(details); Filter();
        if (list.Count == 0) AddEmpty("No findings in this view", Snapshot.Assets.Count == 0 ? "This category is unassessed until evidence is collected." : "No findings are recorded in this view. Coverage and scope determine what this means.");
    }

    private Border FindingDetail(Finding finding)
    {
        var scored = _coordinator.Risk.RankedFindings.FirstOrDefault(s => s.Finding.Id == finding.Id);
        var status = FindingStateLabel(finding, finding.Status == FindingStatus.Open && GetFindingReview(finding.Id));
        var body = Ui.Stack(Ui.Section(finding.Title, finding.Description), Ui.Toolbar(Ui.Badge(finding.Severity.ToString(), SeverityBrush(finding.Severity)), Ui.Badge(status, FindingStateBrush(finding.Status)), Ui.Badge($"{finding.Confidence:P0} evidence confidence", "InfoBrush")),
            Ui.Text($"{finding.Category} · Contextual risk {(scored is null ? "not active in current model" : $"{scored.Risk:0.0} / 100")} · Source {finding.Source}", 13, "MutedBrush"));
        body.Children.Add(InventoryTabs(
            ("Summary", () => FindingSummary(finding, scored)),
            ("Evidence", () => FindingEvidence(finding)),
            ("CVE intelligence", () => FindingIntelligence(finding)),
            ("Contextual risk", () => FindingRisk(finding, scored)),
            ("Attack paths", () => FindingAttackPaths(finding)),
            ("Remediation", () => Ui.Stack(Ui.Section("Defensive remediation", "Apply changes through your approved operational process."), Ui.Text(finding.Remediation), Ui.Section("Verify the fix"), Ui.Text(finding.Verification), Ui.Button("Open remediation workspace", () => Navigate("Remediation"), true))),
            ("History", () => InventoryHistory([finding.Id], finding.FirstSeen, finding.LastSeen)),
            ("Disposition", () => FindingDisposition(finding))));
        return Ui.Card(body);
    }

    private UIElement FindingSummary(Finding finding, ScoredFinding? scored)
    {
        var body = Ui.Stack(Ui.Section("Why this matters"), Ui.Text(scored is null ? "This finding's disposition excludes it from active modeled risk. The original evidence remains available for review." : string.Join("\n", scored.Reasons)), Ui.Section("Affected assets"));
        var assets = Snapshot.Assets.Where(a => finding.AssetIds.Contains(a.Id)).ToList();
        foreach (var asset in assets) body.Children.Add(Ui.Button($"{asset.Name} · {asset.OperatingSystem}", () => OpenAsset(asset.Id)));
        var missing = finding.AssetIds.Except(assets.Select(a => a.Id)).ToList();
        if (missing.Count > 0) body.Children.Add(Ui.Text("Unresolved asset references: " + string.Join(", ", missing), 12, "MutedBrush"));
        if (finding.ControlIds.Count > 0) { body.Children.Add(Ui.Section("Mapped controls")); body.Children.Add(Ui.Text(string.Join(" · ", finding.ControlIds), 13)); body.Children.Add(Ui.Button("Review compliance evidence", () => Navigate("Compliance"))); }
        return body;
    }

    private UIElement FindingEvidence(Finding finding)
    {
        var nodes = Snapshot.Nodes.Where(n => finding.EvidenceIds.Contains(n.Id)).ToList();
        var body = Ui.Stack(Ui.Section("Supporting evidence", $"Source: {finding.Source} · Overall finding confidence {finding.Confidence:P0}"), InventoryEvidenceNodes(nodes));
        var missing = finding.EvidenceIds.Except(nodes.Select(n => n.Id)).ToList();
        if (missing.Count > 0) body.Children.Add(Ui.Text("Evidence references without a graph record: " + string.Join(", ", missing), 12, "MutedBrush"));
        if (finding.EvidenceIds.Count == 0) body.Children.Add(Ui.Text("No explicit graph evidence references. Review the reported source and description before relying on this finding.", 13, "MutedBrush"));
        var observations = Snapshot.Observations.Where(o => finding.AssetIds.Contains(o.AssetId)).OrderByDescending(o => o.ObservedAt).ToList();
        if (observations.Count > 0) { body.Children.Add(Ui.Section("Collected asset observations", "These provide asset context; not every observation supports this finding.")); body.Children.Add(InventoryObservationTable(observations)); }
        return body;
    }

    private UIElement FindingIntelligence(Finding finding)
    {
        var body = Ui.Stack(Ui.Section(string.IsNullOrWhiteSpace(finding.Cve) ? "No CVE recorded" : finding.Cve, "Imported and synthetic intelligence retains its source; SENTINEL does not perform exploitation."),
            Ui.Text($"CVSS {(finding.Cvss > 0 ? finding.Cvss.ToString("0.0") : "No positive value recorded")} · Software {(string.IsNullOrWhiteSpace(finding.Software) ? "Not recorded" : finding.Software)} · Version {(string.IsNullOrWhiteSpace(finding.Version) ? "Not recorded" : finding.Version)}"),
            Ui.Text($"Reported exploitability factor {finding.Exploitability:P0} · Source {finding.Source}", 13, "MutedBrush"));
        if (finding.References.Count == 0) body.Children.Add(Ui.Text("No intelligence references were recorded.", 13, "MutedBrush"));
        else foreach (var reference in finding.References) body.Children.Add(Ui.Text(reference, 13, "InfoBrush"));
        return body;
    }

    private UIElement FindingRisk(Finding finding, ScoredFinding? scored)
    {
        var factors = new[] { ("Technical severity", finding.Severity.ToString()), ("CVSS refinement", finding.Cvss > 0 ? finding.Cvss.ToString("0.0") : "No positive value recorded"), ("Evidence confidence", finding.Confidence.ToString("P0")), ("Exploitability intelligence factor", finding.Exploitability.ToString("P0")), ("Privilege impact factor", finding.PrivilegeImpact.ToString("P0")), ("Identity reach factor", finding.IdentityReach.ToString("P0")), ("Compensating control factor", finding.CompensatingControl.ToString("P0")) };
        var body = Ui.Stack(Ui.Section("Existing contextual risk model", "Risk is an estimate for prioritization, not a breach probability. Active accepted risks remain included."), Ui.Badge(scored is null ? "Not active in current model" : $"{scored.Risk:0.0} / 100", scored is null ? "MutedBrush" : RiskBandBrush(scored.Risk)), InventoryTable(factors.Select(f => new { Factor = f.Item1, Value = f.Item2 }).ToList(), ("Factor", "Factor", 0), ("Recorded input", "Value", 180)));
        if (scored is not null) foreach (var reason in scored.Reasons) body.Children.Add(Ui.Text(reason, 13));
        body.Children.Add(Ui.Text("Visual risk bands: Critical ≥85; High ≥60; Medium ≥30; Low below 30. These bands do not alter scoring.", 12, "MutedBrush"));
        return body;
    }

    private UIElement FindingAttackPaths(Finding finding)
    {
        var paths = _coordinator.AttackPaths.Where(p => p.FindingIds.Contains(finding.Id)).ToList();
        var body = Ui.Stack(Ui.Section("Defensive path participation", "Paths model known evidence and permissions. No path is executed."));
        if (paths.Count == 0) body.Children.Add(Ui.Empty("No active modeled path", "This finding is not part of a current defensive attack path. Evidence completeness still matters.", "Attack Paths"));
        foreach (var path in paths)
            body.Children.Add(Ui.Card(Ui.Stack(Ui.Text(path.Title, 16, bold: true), Ui.Toolbar(Ui.Badge($"Risk {path.Risk:0.0}", RiskBandBrush(path.Risk)), Ui.Badge($"Confidence {path.Confidence:P0}", "InfoBrush")), Ui.Text("Recommended break point: " + path.BreakPoint), Ui.Text(path.RecommendedAction), Ui.Button("Review and break this path", () => Navigate("Attack Paths"), true)), 16));
        return body;
    }

    private UIElement FindingDisposition(Finding finding)
    {
        var selectedState = FindingStateLabel(finding, finding.Status == FindingStatus.Open && GetFindingReview(finding.Id));
        var state = Ui.Select(new[] { "Open", "Under Review", "Remediated", "Accepted Risk", "False Positive" }, selectedState); AutomationProperties.SetName(state, "Finding disposition");
        var reason = Ui.Input(finding.DispositionReason); reason.AcceptsReturn = true; reason.MinHeight = 80; AutomationProperties.SetName(reason, "Disposition reason or verification evidence");
        var expiry = new DatePicker { SelectedDate = finding.AcceptedUntil?.LocalDateTime.Date ?? DateTime.Today.AddDays(30), Margin = new Thickness(0, 0, 8, 8), Width = 180 }; AutomationProperties.SetName(expiry, "Accepted risk review date");
        var body = Ui.Stack(Ui.Section("Audited disposition", "Under Review is a persisted workflow marker; its security disposition stays Open and risk remains modeled."), Ui.Toolbar(state, Ui.Text("Accepted risk review date", 12, "MutedBrush"), expiry), Ui.Text("Reason or verification evidence · required", 12, "MutedBrush"), reason);
        body.Children.Add(Ui.Button("Save disposition", () => _ = GuardAsync(async () =>
        {
            var label = state.SelectedItem?.ToString() ?? "Open";
            if (string.IsNullOrWhiteSpace(reason.Text)) throw new ArgumentException("Record a reason or verification evidence before changing the finding disposition.");
            var status = label switch { "Remediated" => FindingStatus.Fixed, "Accepted Risk" => FindingStatus.AcceptedRisk, "False Positive" => FindingStatus.FalsePositive, _ => FindingStatus.Open };
            if (status == FindingStatus.AcceptedRisk && (expiry.SelectedDate is null || expiry.SelectedDate.Value.Date <= DateTime.Today)) throw new ArgumentException("Accepted risk requires a future review date.");
            await _coordinator.UpdateFindingAsync(finding.Id, status, reason.Text.Trim(), status == FindingStatus.AcceptedRisk ? new DateTimeOffset(expiry.SelectedDate!.Value.Date.AddHours(23)) : null);
            await SetFindingReviewAsync(finding.Id, label == "Under Review", reason.Text.Trim());
            OpenFinding(finding.Id);
            ShowNotice("Finding disposition saved", "The decision was audited and contextual risk recalculated. Reassessment is required to verify an operator-declared fix.");
        }), true));
        body.Children.Add(Ui.Text("Remediated is an operator assertion unless a completed same-scope reassessment verifies the condition. Accepted risk remains visible and modeled until fixed.", 12, "MutedBrush"));
        if (finding.FixedAt is { } fixedAt) body.Children.Add(Ui.Text($"Fixed disposition recorded {fixedAt.LocalDateTime:g}. {finding.DispositionReason}", 13));
        return body;
    }

    private void RenderIdentities(IEnumerable<Identity> identities)
    {
        var list = identities.ToList();
        PageContent.Children.Add(Ui.Columns(Ui.Metric("IDENTITIES", list.Count.ToString("N0"), "Collected source records"), Ui.Metric("PRIVILEGED", list.Count(i => i.IsPrivileged).ToString("N0"), "Recorded privilege designation", "HighBrush"), Ui.Metric("MFA UNKNOWN", list.Count(i => i.MfaEnabled is null).ToString("N0"), "Verify with the identity provider")));
        var search = Ui.Search("Search identities", 300);
        var provider = InventoryFilter("Provider", list.Select(i => i.Provider));
        var privilege = InventoryFilter("Privilege", ["Privileged", "Standard"]);
        var mfa = InventoryFilter("MFA", ["Enabled", "Not enabled", "Unknown"]);
        var activity = InventoryFilter("Activity evidence", ["Recent recorded sign-in", "Review · >90 days", "Unknown"]);
        var rows = list.Select(i => new IdentityRow(i)).ToList();
        var grid = InventoryTable(rows, ("Identity", "DisplayName", 0), ("Principal", "PrincipalName", 255), ("Provider", "Provider", 220), ("Privilege", "Privileged", 125), ("MFA", "Mfa", 140), ("Activity evidence", "Activity", 185), ("Last sign-in", "LastSignIn", 170));
        InventoryBadgeColumn(grid, "Privilege", "Privileged", "PrivilegeBrush"); InventoryBadgeColumn(grid, "MFA", "Mfa", "MfaBrush"); InventoryBadgeColumn(grid, "Activity evidence", "Activity", "ActivityBrush");
        InventorySortColumn(grid, "Last sign-in", "Identity.LastSignIn");
        InventoryAdaptiveColumns(grid, "Last sign-in", "Principal", "Provider");
        var count = Ui.Text("", 12, "MutedBrush"); var detail = new StackPanel();
        void Filter()
        {
            var filtered = rows.Where(i => MatchesInventoryFilter(provider, i.Provider) && MatchesInventoryFilter(privilege, i.Privileged) && MatchesInventoryFilter(mfa, i.Mfa) && MatchesInventoryFilter(activity, i.Activity) &&
                $"{i.DisplayName} {i.PrincipalName} {i.Provider} {string.Join(' ', i.Identity.Groups)} {string.Join(' ', i.Identity.Permissions)}".Contains(search.Text.Trim(), StringComparison.OrdinalIgnoreCase)).ToList();
            grid.ItemsSource = filtered; count.Text = $"{filtered.Count:N0} of {rows.Count:N0} identities · sign-in age is a review signal, not proof of abandonment";
            detail.Children.Clear(); if (filtered.Count == 0) detail.Children.Add(Ui.Empty("No matching identities", "Adjust filters or collect authorized provider evidence.", "Identity"));
        }
        search.TextChanged += (_, _) => Filter(); foreach (var filter in new[] { provider, privilege, mfa, activity }) filter.SelectionChanged += (_, _) => Filter();
        grid.SelectionChanged += (_, _) =>
        {
            detail.Children.Clear();
            if (grid.SelectedItem is not IdentityRow row) return;
            detail.Children.Add(IdentityDetail(row.Identity));
            _ = Dispatcher.InvokeAsync(() => detail.BringIntoView(), System.Windows.Threading.DispatcherPriority.Loaded);
        };
        PageContent.Children.Add(Ui.Card(Ui.Stack(Ui.Section("Identity posture", "Review privilege, MFA evidence and explicit relationships without collecting credentials."), Ui.Toolbar(search, provider, privilege, mfa, activity), count, grid))); PageContent.Children.Add(detail); Filter();
        if (list.Count == 0) AddEmpty("Identity posture is unassessed", "No identity records have been collected. Offline imports do not establish an active cloud or directory API connection.");
    }

    private Border IdentityDetail(Identity identity)
    {
        var node = Snapshot.Nodes.FirstOrDefault(n => n.Id == identity.Id);
        var related = Snapshot.Edges.Where(e => e.SourceId == identity.Id || e.TargetId == identity.Id).ToList();
        var findings = Snapshot.Findings.Where(f => f.EvidenceIds.Contains(identity.Id) || related.Any(e => e.FindingIds.Contains(f.Id))).ToList();
        var paths = _coordinator.AttackPaths.Where(p => p.NodeIds.Contains(identity.Id)).ToList();
        var body = Ui.Stack(Ui.Section(identity.DisplayName, $"{identity.PrincipalName} · {identity.Provider}"), Ui.Toolbar(Ui.Badge(identity.IsPrivileged ? "Privileged" : "Standard", identity.IsPrivileged ? "HighBrush" : "MutedBrush"), Ui.Badge("MFA " + (identity.MfaEnabled is null ? "Unknown" : identity.MfaEnabled.Value ? "Enabled" : "Not enabled"), identity.MfaEnabled == false ? "HighBrush" : "MutedBrush")), Ui.Text($"Last recorded sign-in: {identity.LastSignIn?.LocalDateTime.ToString("g") ?? "Unknown"} · {paths.Count} active defensive paths", 13), Ui.Text(node is null ? "Graph provenance unavailable for this identity record." : $"Source {node.Source} · Confidence {node.Confidence:P0} · Observed {node.ObservedAt.LocalDateTime:g}", 12, "MutedBrush"));
        body.Children.Add(InventoryTabs(
            ("Overview", () => Ui.Stack(Ui.Section("Recorded identity posture"), Ui.Text("A missing MFA value is unknown. Last-sign-in age requires owner review and provider evidence; service accounts can have legitimate exceptions.", 13, "MutedBrush"), Ui.Section("Groups"), Ui.Text(identity.Groups.Count == 0 ? "No group membership recorded." : string.Join("\n", identity.Groups.Select(id => Snapshot.Nodes.FirstOrDefault(n => n.Id == id)?.Label ?? id))), Ui.Section("Recorded permissions"), Ui.Text(identity.Permissions.Count == 0 ? "No permission records collected." : string.Join("\n", identity.Permissions)))),
            ("Relationships", () => Ui.Stack(InventoryRelationshipTable(related), Ui.Button("Focus identity in evidence graph", () => OpenEvidence(identity.Id), true))),
            ("Findings", () => InventoryFindingLinks(findings)),
            ("History", () => InventoryHistory([identity.Id], node?.ObservedAt, node?.ObservedAt))));
        return Ui.Card(body);
    }

    private HashSet<string> AssetNodeIds(Asset asset) => Snapshot.Nodes.Where(n => n.Id == asset.Id ||
        ((n.Kind is EvidenceKind.Asset or EvidenceKind.CloudResource) && n.Properties.GetValueOrDefault("assetId") == asset.Id)).Select(n => n.Id).Append(asset.Id).ToHashSet();
    private IReadOnlyList<EvidenceNode> AssetDirectNodes(Asset asset)
    {
        var roots = AssetNodeIds(asset); var ids = Snapshot.Edges.Where(e => roots.Contains(e.SourceId) || roots.Contains(e.TargetId)).Select(e => roots.Contains(e.SourceId) ? e.TargetId : e.SourceId).ToHashSet();
        return Snapshot.Nodes.Where(n => ids.Contains(n.Id)).ToList();
    }
    private UIElement InventoryFindingLinks(IReadOnlyList<Finding> findings)
    {
        if (findings.Count == 0) return Ui.Empty("No linked findings", "No findings are recorded for this record. Collection coverage can still be incomplete.", "Vulnerabilities");
        var risks = _coordinator.Risk.RankedFindings.ToDictionary(f => f.Finding.Id);
        var table = InventoryTable(findings.Select(f => new { Finding = f, f.Title, Severity = f.Severity.ToString(), Risk = risks.TryGetValue(f.Id, out var r) ? r.Risk.ToString("0.0") : "Not active", State = FindingStateLabel(f, f.Status == FindingStatus.Open && GetFindingReview(f.Id)), LastSeen = f.LastSeen.LocalDateTime.ToString("g") }).ToList(), ("Finding", "Title", 0), ("Severity", "Severity", 125), ("Contextual risk", "Risk", 145), ("State", "State", 145), ("Last seen", "LastSeen", 165));
        table.SelectionChanged += (_, _) => { if (table.SelectedItem is not null && table.SelectedItem.GetType().GetProperty("Finding")?.GetValue(table.SelectedItem) is Finding selected) OpenFinding(selected.Id); };
        return Ui.Stack(Ui.Section("Linked findings", "Select a finding to inspect evidence, remediation and audited disposition."), table);
    }
    private UIElement InventoryEvidenceNodes(IReadOnlyList<EvidenceNode> nodes)
    {
        if (nodes.Count == 0) return Ui.Empty("No graph evidence records", "Review the source and observations; no explicit graph nodes are available in this view.", "Evidence Graph");
        var table = InventoryTable(nodes.Select(n => new { Node = n, n.Label, Type = n.Kind.ToString(), n.Source, Confidence = n.Confidence.ToString("P0"), Observed = n.ObservedAt.LocalDateTime.ToString("g") }).ToList(), ("Evidence", "Label", 0), ("Type", "Type", 145), ("Source", "Source", 170), ("Confidence", "Confidence", 100), ("Observed", "Observed", 165));
        table.SelectionChanged += (_, _) => { if (table.SelectedItem is not null && table.SelectedItem.GetType().GetProperty("Node")?.GetValue(table.SelectedItem) is EvidenceNode selected) OpenEvidence(selected.Id); };
        return table;
    }
    private UIElement InventoryRelationshipTable(IReadOnlyList<EvidenceEdge> edges)
    {
        if (edges.Count == 0) return Ui.Text("No explicit graph relationships recorded.", 13, "MutedBrush");
        var nodes = Snapshot.Nodes.ToDictionary(n => n.Id);
        return InventoryTable(edges.Select(e => new { Source = nodes.GetValueOrDefault(e.SourceId)?.Label ?? e.SourceId, e.Relationship, Target = nodes.GetValueOrDefault(e.TargetId)?.Label ?? e.TargetId, Confidence = e.Confidence.ToString("P0"), BreakPoint = e.DefensiveBreak }).ToList(), ("From", "Source", 0), ("Relationship", "Relationship", 220), ("To", "Target", 220), ("Confidence", "Confidence", 100));
    }
    private UIElement InventoryHistory(IEnumerable<string> entityIds, DateTimeOffset? first, DateTimeOffset? last)
    {
        var ids = entityIds.ToHashSet(); var changes = Snapshot.Changes.Where(c => ids.Contains(c.EntityId)).OrderByDescending(c => c.At).ToList();
        var body = Ui.Stack(Ui.Section("Recorded history", "Only linked evidence changes are shown. Environment score history is not an individual record's risk history."), Ui.Text($"First recorded: {first?.LocalDateTime.ToString("g") ?? "Unknown"} · Last observed: {last?.LocalDateTime.ToString("g") ?? "Unknown"}", 13));
        if (changes.Count == 0) body.Children.Add(Ui.Empty("No linked change events", "Record timestamps remain available; no additional historical events are linked.", "Monitoring"));
        else body.Children.Add(InventoryTable(changes.Select(c => new { At = c.At.LocalDateTime.ToString("g"), c.Kind, c.Summary, c.Source, c.EntityId }).ToList(), ("Time", "At", 170), ("Event", "Kind", 175), ("Recorded change", "Summary", 0), ("Source", "Source", 170)));
        var observations = Snapshot.Observations.Where(o => ids.Contains(o.AssetId)).OrderByDescending(o => o.ObservedAt).ToList();
        if (observations.Count > 0) { body.Children.Add(Ui.Section("Observation history")); body.Children.Add(InventoryObservationTable(observations)); }
        return body;
    }
    private static DataGrid InventoryObservationTable(IEnumerable<Observation> observations) => InventoryTable(observations.Select(o => new { o.Property, o.Value, o.Source, o.EngineId, Observed = o.ObservedAt.LocalDateTime.ToString("g") }).ToList(), ("Property", "Property", 190), ("Recorded value", "Value", 0), ("Source", "Source", 160), ("Observed", "Observed", 165));
    private static TabControl InventoryTabs(params (string Label, Func<UIElement> Build)[] sections)
    {
        var tabs = new TabControl { Margin = new Thickness(0, 16, 0, 0) }; AutomationProperties.SetName(tabs, "Record detail workspace");
        foreach (var section in sections) tabs.Items.Add(new TabItem { Header = section.Label, Tag = section.Build });
        tabs.SelectionChanged += (_, e) => { if (e.Source == tabs && tabs.SelectedItem is TabItem { Content: null, Tag: Func<UIElement> build } item) item.Content = new Border { Child = build(), Padding = new Thickness(0, 16, 0, 0) }; };
        tabs.SelectedIndex = 0;
        if (tabs.Items.Count > 0 && tabs.Items[0] is TabItem { Content: null, Tag: Func<UIElement> initial } first) first.Content = new Border { Child = initial(), Padding = new Thickness(0, 16, 0, 0) };
        return tabs;
    }
    private static ComboBox InventoryFilter(string label, IEnumerable<string> values)
    {
        var combo = Ui.Select(new[] { "All · " + label }.Concat(values.Where(v => !string.IsNullOrWhiteSpace(v)).Distinct()), "All · " + label); combo.MaxWidth = 260; AutomationProperties.SetName(combo, label); combo.ToolTip = label; return combo;
    }
    private static bool MatchesInventoryFilter(ComboBox filter, string value) => filter.SelectedIndex <= 0 || string.Equals(filter.SelectedItem?.ToString(), value, StringComparison.Ordinal);
    private static DataGrid InventoryTable(IEnumerable source, params (string Heading, string Path, double Width)[] columns)
    {
        var table = Ui.Table(source, columns); table.Height = 352; table.EnableRowVirtualization = true; table.EnableColumnVirtualization = true; table.SelectionMode = DataGridSelectionMode.Single;
        VirtualizingPanel.SetIsVirtualizing(table, true); VirtualizingPanel.SetVirtualizationMode(table, VirtualizationMode.Recycling); ScrollViewer.SetCanContentScroll(table, true); ScrollViewer.SetHorizontalScrollBarVisibility(table, ScrollBarVisibility.Auto);
        AutomationProperties.SetName(table, "Evidence inventory table"); return table;
    }
    private static void InventoryAdaptiveColumns(DataGrid table, params string[] lowerPriority)
    {
        table.SizeChanged += (_, _) =>
        {
            var hiddenCount = table.ActualWidth < 620 ? lowerPriority.Length : table.ActualWidth < 820 ? Math.Max(0, lowerPriority.Length - 1) : table.ActualWidth < 1100 ? Math.Min(2, lowerPriority.Length) : 0;
            for (var i = 0; i < lowerPriority.Length; i++) { var column = table.Columns.FirstOrDefault(c => c.Header?.ToString() == lowerPriority[i]); if (column is not null) column.Visibility = i < hiddenCount ? Visibility.Collapsed : Visibility.Visible; }
        };
    }
    private static void InventoryBadgeColumn(DataGrid table, string heading, string valuePath, string colorPath, string? tooltipPath = null)
    {
        var old = table.Columns.First(c => c.Header?.ToString() == heading); var index = table.Columns.IndexOf(old);
        var presenter = new FrameworkElementFactory(typeof(ContentPresenter));
        var binding = new MultiBinding { Converter = new InventoryBadgeConverter() }; binding.Bindings.Add(new Binding(valuePath)); binding.Bindings.Add(new Binding(colorPath)); presenter.SetBinding(ContentPresenter.ContentProperty, binding);
        if (tooltipPath is not null) presenter.SetBinding(FrameworkElement.ToolTipProperty, new Binding(tooltipPath));
        table.Columns.RemoveAt(index); table.Columns.Insert(index, new DataGridTemplateColumn { Header = heading, Width = old.Width, MinWidth = old.MinWidth, SortMemberPath = valuePath, CellTemplate = new DataTemplate { VisualTree = presenter } });
    }
    private static void InventorySortColumn(DataGrid table, string heading, string valuePath)
        => table.Columns.First(c => c.Header?.ToString() == heading).SortMemberPath = valuePath;
    private sealed class InventoryBadgeConverter : IMultiValueConverter
    {
        public object Convert(object[] values, Type targetType, object parameter, CultureInfo culture)
        {
            var label = values.ElementAtOrDefault(0);
            var color = values.ElementAtOrDefault(1);
            return Ui.Badge(label is null || ReferenceEquals(label, DependencyProperty.UnsetValue) ? "Unknown" : label.ToString() ?? "Unknown",
                color is null || ReferenceEquals(color, DependencyProperty.UnsetValue) ? "MutedBrush" : color.ToString() ?? "MutedBrush");
        }
        public object[] ConvertBack(object value, Type[] targetTypes, object parameter, CultureInfo culture) => throw new NotSupportedException();
    }
    private static string AssetStatus(Asset asset) => asset.Properties.GetValueOrDefault("lifecycle") == "Operator retired" ? "Operator retired" : "Observed";
    private static string CriticalityLabel(int value) => value switch { >= 5 => "Critical · 5/5", 4 => "Important · 4/5", 3 => "Standard · 3/5", 2 => "Supporting · 2/5", _ => "Low · 1/5" };
    private static string RiskBand(double? risk) => risk is null ? "Not modeled" : risk >= 85 ? "Critical" : risk >= 60 ? "High" : risk >= 30 ? "Medium" : "Low";
    private static string RiskBandBrush(double? risk) => risk is null ? "MutedBrush" : risk >= 85 ? "CriticalBrush" : risk >= 60 ? "HighBrush" : risk >= 30 ? "MediumBrush" : "LowBrush";
    private static string FindingStateLabel(Finding finding, bool review = false) => review ? "Under Review" : finding.Status switch { FindingStatus.Fixed => "Remediated", FindingStatus.AcceptedRisk => "Accepted Risk", FindingStatus.FalsePositive => "False Positive", _ => "Open" };
    private static string FindingStateBrush(FindingStatus status) => status switch { FindingStatus.Fixed => "SuccessBrush", FindingStatus.AcceptedRisk => "HighBrush", FindingStatus.FalsePositive => "MutedBrush", _ => "InfoBrush" };
    private sealed record AssetInventoryRow(Asset Asset, IReadOnlyList<ScoredFinding> Findings, DateTimeOffset? LastObservation)
    {
        public string Name => Asset.Name; public string Kind => Asset.Kind.ToString(); public string Address => Asset.Address; public string OperatingSystem => Asset.OperatingSystem; public string Owner => Asset.Owner;
        public string Status => AssetStatus(Asset); public string StatusBrush => "MutedBrush"; public string Criticality => CriticalityLabel(Asset.BusinessCriticality); public string CriticalityBrush => Asset.IsCritical ? "HighBrush" : "MutedBrush";
        public string CriticalityDetail => $"Business criticality {Asset.BusinessCriticality} / 5"; public double? PeakRisk => Findings.Count == 0 ? null : Findings.Max(f => f.Risk); public string RiskLevel => RiskBand(PeakRisk); public string RiskDisplay => PeakRisk is null ? "Not modeled" : $"{PeakRisk:0.0} · {RiskLevel}"; public string RiskBrush => RiskBandBrush(PeakRisk);
        public string RiskExplanation => "Highest linked active finding risk /100. Includes accepted risk; excludes remediated and false-positive findings. Not an asset security score."; public int FindingCount => Findings.Count; public string LastAssessed => LastObservation?.LocalDateTime.ToString("g") ?? "No observation";
    }
    private sealed record FindingRow(Finding Finding, double? Risk, IReadOnlyList<Asset> Assets, bool UnderReview)
    {
        public string Title => Finding.Title; public string Severity => Finding.Severity.ToString(); public string SeverityBrush => MainWindow.SeverityBrush(Finding.Severity); public string RiskDisplay => Risk is null ? "Not active" : $"{Risk:0.0} / 100"; public string RiskBrush => RiskBandBrush(Risk); public string RiskExplanation => "Existing contextual finding risk: evidence confidence, technical severity, exposure, business importance, identity reach and defensive path participation.";
        public string Cve => string.IsNullOrWhiteSpace(Finding.Cve) ? "Not recorded" : Finding.Cve; public int AssetCount => Finding.AssetIds.Distinct().Count(); public string Status => FindingStateLabel(Finding, UnderReview); public string StatusBrush => FindingStateBrush(Finding.Status); public string Confidence => Finding.Confidence.ToString("P0"); public string ConfidenceBand => Finding.Confidence >= .9 ? "90–100%" : Finding.Confidence >= .7 ? "70–89%" : "Below 70%"; public string LastSeen => Finding.LastSeen.LocalDateTime.ToString("g"); public double ExposureFactor => Assets.Count == 0 ? 0 : Assets.Max(a => a.Exposure); public string Exposure => ExposureFactor >= .7 ? "High exposure factor" : ExposureFactor > 0 ? "Recorded exposure" : "No factor recorded";
    }
    private sealed record IdentityRow(Identity Identity)
    {
        public string DisplayName => Identity.DisplayName; public string PrincipalName => Identity.PrincipalName; public string Provider => Identity.Provider; public string Privileged => Identity.IsPrivileged ? "Privileged" : "Standard"; public string PrivilegeBrush => Identity.IsPrivileged ? "HighBrush" : "MutedBrush"; public string Mfa => Identity.MfaEnabled is null ? "Unknown" : Identity.MfaEnabled.Value ? "Enabled" : "Not enabled"; public string MfaBrush => Identity.MfaEnabled == false ? "HighBrush" : Identity.MfaEnabled == true ? "SuccessBrush" : "MutedBrush"; public string LastSignIn => Identity.LastSignIn?.LocalDateTime.ToString("g") ?? "Unknown"; public string Activity => Identity.LastSignIn is null ? "Unknown" : Identity.LastSignIn < DateTimeOffset.UtcNow.AddDays(-90) ? "Review · >90 days" : "Recent recorded sign-in"; public string ActivityBrush => Activity.StartsWith("Review", StringComparison.Ordinal) ? "MediumBrush" : "MutedBrush";
    }
}
