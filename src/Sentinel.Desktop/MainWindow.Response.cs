using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using Microsoft.Win32;
using Sentinel.Core;
using Sentinel.Infrastructure;

namespace Sentinel.Desktop;

public partial class MainWindow
{
    private readonly Dictionary<string, List<AnalystTurn>> _analystConversations = new(StringComparer.Ordinal);

    private bool GetFindingReview(string id) => _workflow.IsUnderReview(id);

    private async Task SetFindingReviewAsync(string id, bool underReview, string reason)
    {
        var environmentId = Snapshot.Id;
        if (!Snapshot.Findings.Any(f => f.Id == id)) throw new ArgumentException("This finding is no longer available.");
        await _workflow.SetUnderReviewAsync(id, underReview, reason, environmentId: environmentId);
        await _repository.AuditAsync(new(DateTimeOffset.UtcNow, "finding.review.updated", id,
            $"Environment={environmentId}; underReview={underReview}; {reason.Trim()}", Guid.NewGuid().ToString("N")[..12]));
    }

    private void RenderRemediation()
    {
        var actions = _coordinator.Remediations.OrderByDescending(a => a.ModeledRiskReduction).ToList();
        var saved = _workflow.Plans;
        var verified = saved.Count(p => p.EvidenceState(Snapshot) == "Verified");
        PageContent.Children.Add(Ui.Columns(
            Ui.Metric("PRIORITIZED ACTIONS", actions.Count.ToString(), "Root causes grouped from current evidence"),
            Ui.Metric("WORK IN PROGRESS", saved.Count(p => p.Status is "Planned" or "In Progress").ToString(), "Saved ownership and planning status", "AccentBrush"),
            Ui.Metric("AWAITING VERIFICATION", saved.Count(p => p.Status == "Awaiting Verification" && p.EvidenceState(Snapshot) != "Verified").ToString(), "A new assessment must confirm the fix", "HighBrush"),
            Ui.Metric("EVIDENCE VERIFIED", verified.ToString(), "Same engine completed a clean reassessment", "SuccessBrush")));
        PageContent.Children.Add(Ui.Card(Ui.Stack(Ui.Text("A defensible order of action", 20, bold: true),
            Ui.Text("The plan groups related findings by root cause. Associated risk is an estimate, not a guarantee. Planning status and ownership never change scan evidence or security scores. Verified is derived from completed assessment evidence and cannot be selected manually.", brush: "MutedBrush"))));

        var search = Ui.Search("Search actions, root causes, or owners", 330);
        var state = Ui.Select(new[] { "All statuses", "Recommended", "Planned", "In Progress", "Awaiting Verification", "Verified", "Accepted" }, "All statuses");
        AutomationProperties.SetName(state, "Remediation status filter");
        var list = new StackPanel();
        void Refresh()
        {
            list.Children.Clear();
            var currentIds = actions.Select(a => a.Id).ToHashSet(StringComparer.Ordinal);
            var plans = actions.Select(a => _workflow.GetPlan(a.Id) ?? RemediationPlan.FromAction(a, Snapshot))
                .Concat(saved.Where(p => !currentIds.Contains(p.ActionId))).ToList();
            var count = 0;
            foreach (var plan in plans)
            {
                var verification = plan.EvidenceState(Snapshot);
                var displayedStatus = verification == "Verified" ? "Verified" : plan.Status;
                if (state.SelectedItem?.ToString() != "All statuses" && displayedStatus != state.SelectedItem?.ToString()) continue;
                if (!$"{plan.Title} {plan.Owner} {string.Join(' ', plan.RootCauseKeys)}".Contains(search.Text, StringComparison.OrdinalIgnoreCase)) continue;
                var currentAction = actions.FirstOrDefault(a => a.Id == plan.ActionId);
                list.Children.Add(BuildRemediationCard(plan, currentAction, ++count));
            }
            if (count == 0) list.Children.Add(Ui.Card(Ui.Stack(Ui.Text("No actions match this view", 18, bold: true),
                Ui.Text(actions.Count == 0 && saved.Count == 0 ? "Collect authorized evidence to establish priorities. An empty plan does not establish that unassessed assets are secure." : "Change the search or status filter to review the remaining work.", brush: "MutedBrush"))));
        }
        search.TextChanged += (_, _) => Refresh();
        state.SelectionChanged += (_, _) => Refresh();
        PageContent.Children.Add(Ui.Toolbar(search, state));
        PageContent.Children.Add(list);
        Refresh();
    }

    private UIElement BuildRemediationCard(RemediationPlan plan, RemediationAction? current, int priority)
    {
        var evidenceState = plan.EvidenceState(Snapshot);
        var statusText = evidenceState == "Verified" ? "Verified" : plan.Status;
        var related = Snapshot.Findings.Where(f => plan.FindingIds.Contains(f.Id)).ToList();
        var severity = related.Count == 0 ? Severity.Informational : related.Max(f => f.Severity);
        var reduction = current?.ModeledRiskReduction;
        var estimate = reduction is null ? $"Saved baseline: {plan.ModeledRiskReduction:0.0} modeled points · not a current reduction estimate"
            : $"{reduction:0.0} modeled points associated · {(_coordinator.Risk.TotalRisk > 0 ? Math.Min(100, reduction.Value / _coordinator.Risk.TotalRisk * 100) : 0):0.0}% of current modeled risk";
        var badges = Ui.Toolbar(Ui.Badge($"Priority {priority}", "AccentBrush"), Ui.Badge(severity.ToString(), SeverityBrush(severity)),
            Ui.Badge(statusText, evidenceState == "Verified" ? "SuccessBrush" : "MutedBrush"), Ui.Badge($"{plan.AssetIds.Count} assets", "MutedBrush"),
            Ui.Badge($"{plan.FindingIds.Count} findings", "MutedBrush"));
        var body = Ui.Stack(badges, Ui.Text(plan.Title, 20, bold: true), Ui.Text(current?.Why ?? plan.Why, brush: "MutedBrush"),
            Ui.Text(estimate, 14, "AccentBrush"), Ui.Text($"Evidence confidence: {(current?.Confidence ?? plan.Confidence):P0} · Owner: {plan.Owner} · {evidenceState}", 12, "MutedBrush"));
        var details = Ui.Stack(Ui.Text("Required defensive action", 17, bold: true), Ui.Text(current?.Instructions ?? plan.Instructions),
            Ui.Text("How to verify", 17, bold: true), Ui.Text(current?.Verification ?? plan.Verification),
            Ui.Text("The same engine must complete a new assessment of all affected assets without observing this condition. An operator marking a finding Fixed remains an operator assertion until matching completion and resolution evidence exists.", 12, "MutedBrush"));
        var references = Ui.Toolbar();
        foreach (var asset in Snapshot.Assets.Where(a => plan.AssetIds.Contains(a.Id)))
            references.Children.Add(Ui.Button($"Asset: {asset.Name}", () => OpenAsset(asset.Id)));
        foreach (var finding in related)
            references.Children.Add(Ui.Button($"Finding: {finding.Title}", () => OpenFinding(finding.Id)));
        details.Children.Add(Ui.Text("Affected records", 17, bold: true));
        details.Children.Add(references);
        var evidenceLinks = Ui.Toolbar();
        foreach (var node in Snapshot.Nodes.Where(n => plan.EvidenceIds.Contains(n.Id)).Take(16))
            evidenceLinks.Children.Add(Ui.Button(node.Label, () => OpenEvidence(node.Id)));
        details.Children.Add(Ui.Text("Supporting evidence", 17, bold: true));
        details.Children.Add(evidenceLinks);
        if (evidenceLinks.Children.Count == 0) details.Children.Add(Ui.Text("No matching evidence nodes remain in this snapshot. Review retention and scope before accepting conclusions.", 12, "MutedBrush"));

        var editableStatus = Ui.Select(RemediationPlan.EditableStatuses, plan.Status);
        AutomationProperties.SetName(editableStatus, "Remediation planning status");
        var owner = Ui.Input(plan.Owner, 260);
        AutomationProperties.SetName(owner, "Remediation owner");
        owner.MaxLength = 256;
        var note = Ui.Input();
        note.MaxLength = 4096;
        note.ToolTip = "Record an implementation update, owner decision, or verification evidence reference";
        AutomationProperties.SetName(note, "Remediation planning note");
        details.Children.Add(Ui.Text("Plan and ownership", 17, bold: true));
        details.Children.Add(Ui.Toolbar(editableStatus, owner));
        details.Children.Add(Ui.Text("Update note (required)", 12, "MutedBrush"));
        details.Children.Add(note);
        var save = Ui.Button("Save remediation plan", () => _ = GuardAsync(async () =>
        {
            if (string.IsNullOrWhiteSpace(note.Text)) throw new ArgumentException("Record an update note before saving the remediation plan.");
            var candidate = _workflow.GetPlan(plan.ActionId) ?? plan;
            candidate.Status = editableStatus.SelectedItem?.ToString() ?? "Recommended";
            candidate.Owner = string.IsNullOrWhiteSpace(owner.Text) ? "Unassigned" : owner.Text.Trim();
            candidate.UpdatedAt = DateTimeOffset.UtcNow;
            candidate.Notes.Add(new(candidate.UpdatedAt, Environment.UserName, note.Text.Trim()));
            await _workflow.SavePlanAsync(candidate);
            await _repository.AuditAsync(new(candidate.UpdatedAt, "remediation.plan.updated", candidate.ActionId,
                $"Environment={candidate.EnvironmentId}; status={candidate.Status}; owner={candidate.Owner}; {note.Text.Trim()}", Guid.NewGuid().ToString("N")[..12]));
            RenderPage();
            ShowNotice("Remediation plan saved", "Ownership and planning status were audited. No fix was executed and no risk reduction was claimed.");
        }), true);
        details.Children.Add(Ui.Toolbar(save, Ui.Button("Start verification assessment", () =>
        {
            if (Snapshot.Mode == EnvironmentMode.Demo)
                ShowNotice("Demo verification stays offline", "Synthetic demo evidence cannot verify a real fix. Review the supporting records and verification instructions; use a separately authorized Live Environment assessment for real verification.");
            else ScanButton_Click();
        })));
        if (plan.Status == "Accepted") details.Children.Add(Ui.Text("Accepted here records the operator's planning decision. Finding-level risk acceptance and a review date are managed in the finding disposition workspace.", 12, "HighBrush"));
        foreach (var entry in plan.Notes.OrderByDescending(n => n.At).Take(10))
            details.Children.Add(Ui.Text($"{entry.At.LocalDateTime:g} · {entry.Author}\n{entry.Text}", 12, "MutedBrush"));
        var expander = new Expander { Header = "Review action, evidence, and verification", Content = details, Margin = new Thickness(0, 8, 0, 0) };
        AutomationProperties.SetName(expander, $"Review remediation: {plan.Title}");
        body.Children.Add(expander);
        return Ui.Card(body);
    }

    private UIElement ActionSummary(RemediationAction action)
    {
        var related = Snapshot.Findings.Where(f => action.FindingIds.Contains(f.Id)).ToList();
        var severity = related.Count == 0 ? Severity.Informational : related.Max(f => f.Severity);
        var plan = _workflow.GetPlan(action.Id);
        return Ui.Stack(Ui.Toolbar(Ui.Badge(severity.ToString(), SeverityBrush(severity)), Ui.Badge($"{action.AssetIds.Count} assets", "MutedBrush"),
                Ui.Badge(plan?.Status ?? "Recommended", "AccentBrush")),
            Ui.Text(action.Title, 16, bold: true),
            Ui.Text($"{(_coordinator.Risk.TotalRisk > 0 ? Math.Min(100, action.ModeledRiskReduction / _coordinator.Risk.TotalRisk * 100) : 0):0}% of modeled risk associated · {action.Confidence:P0} evidence confidence", 12, "MutedBrush"),
            Ui.Text("Verification pending · effort not estimated from evidence", 12, "MutedBrush"),
            Ui.Button("Review remediation", () => Navigate("Remediation")));
    }

    private void RenderIncidents()
    {
        var incidents = Snapshot.Incidents.OrderByDescending(i => i.UpdatedAt).ToList();
        PageContent.Children.Add(Ui.Columns(Ui.Metric("ACTIVE INVESTIGATIONS", incidents.Count(i => i.Status is "Open" or "Investigating").ToString(), "Operator-managed local investigations", "AccentBrush"),
            Ui.Metric("CONTAINED", incidents.Count(i => i.Status == "Contained").ToString(), "Operator status · no containment executed"),
            Ui.Metric("RESOLVED", incidents.Count(i => i.Status == "Resolved").ToString(), "Resolution notes retained in the audit trail", "SuccessBrush")));
        PageContent.Children.Add(Ui.Card(Ui.Stack(Ui.Text("Investigate connected evidence", 20, bold: true),
            Ui.Text("Group related findings into an investigation with an owner, updates, and a timeline. A posture finding does not establish a confirmed incident. Investigation status records operator decisions; SENTINEL does not perform remote containment.", brush: "MutedBrush"))));
        var title = Ui.Input(); title.MaxLength = 1024; AutomationProperties.SetName(title, "Investigation title");
        var owner = Ui.Input(Environment.UserName, 260); AutomationProperties.SetName(owner, "Investigation owner");
        var candidates = Snapshot.Findings.Where(f => f.Status == FindingStatus.Open).OrderByDescending(f => f.Severity).ToList();
        var findings = new ListBox { ItemsSource = candidates, DisplayMemberPath = "Title", SelectionMode = SelectionMode.Multiple, MaxHeight = 220, MinHeight = 96 };
        AutomationProperties.SetName(findings, "Supporting findings for investigation");
        VirtualizingPanel.SetIsVirtualizing(findings, true);
        var selectedCount = Ui.Text("Select one or more supporting findings. Use Ctrl or Shift for multiple selection.", 12, "MutedBrush");
        findings.SelectionChanged += (_, _) => selectedCount.Text = $"{findings.SelectedItems.Count} supporting findings selected · evidence links will be retained";
        var create = Ui.Button("Create investigation", () => _ = GuardAsync(async () =>
        {
            var ids = findings.SelectedItems.Cast<Finding>().Select(f => f.Id).ToArray();
            if (ids.Length == 0) throw new ArgumentException("Select at least one supporting finding.");
            await _coordinator.CreateIncidentAsync(title.Text, owner.Text, ids);
            RenderPage(); ShowNotice("Investigation created", "The owner and related finding references were recorded in the audit trail.");
        }), true);
        var creation = new Expander { Header = "New investigation", Content = Ui.Stack(Ui.Text("Title", 12, "MutedBrush"), title,
            Ui.Text("Owner", 12, "MutedBrush"), owner, findings, selectedCount, create), IsExpanded = incidents.Count == 0, Margin = new Thickness(0, 0, 0, 16) };
        PageContent.Children.Add(Ui.Card(creation));

        var search = Ui.Search("Search investigations or owners", 340);
        var statusFilter = Ui.Select(new[] { "All statuses", "Open", "Investigating", "Contained", "Resolved" }, "All statuses");
        AutomationProperties.SetName(statusFilter, "Investigation status filter");
        var list = new StackPanel();
        void Refresh()
        {
            list.Children.Clear();
            foreach (var incident in incidents.Where(i => (statusFilter.SelectedItem?.ToString() == "All statuses" || i.Status == statusFilter.SelectedItem?.ToString()) &&
                $"{i.Title} {i.Owner}".Contains(search.Text, StringComparison.OrdinalIgnoreCase))) list.Children.Add(BuildIncidentCard(incident));
            if (list.Children.Count == 0) list.Children.Add(Ui.Card(Ui.Stack(Ui.Text("No investigations in this view", 18, bold: true),
                Ui.Text("Create an investigation from observed findings or change the search and status filter.", brush: "MutedBrush"))));
        }
        search.TextChanged += (_, _) => Refresh(); statusFilter.SelectionChanged += (_, _) => Refresh();
        PageContent.Children.Add(Ui.Toolbar(search, statusFilter)); PageContent.Children.Add(list); Refresh();
    }

    private UIElement BuildIncidentCard(IncidentRecord incident)
    {
        var related = Snapshot.Findings.Where(f => incident.FindingIds.Contains(f.Id)).ToList();
        var assets = related.SelectMany(f => f.AssetIds).ToHashSet(StringComparer.Ordinal);
        var highest = related.Count == 0 ? Severity.Informational : related.Max(f => f.Severity);
        var body = Ui.Stack(Ui.Toolbar(Ui.Badge(incident.Status, incident.Status == "Resolved" ? "SuccessBrush" : "AccentBrush"), Ui.Badge(highest.ToString(), SeverityBrush(highest)),
            Ui.Badge($"{related.Count} findings", "MutedBrush"), Ui.Badge($"{assets.Count} assets", "MutedBrush")),
            Ui.Text(incident.Title, 20, bold: true), Ui.Text($"Owner: {incident.Owner} · Created {incident.CreatedAt.LocalDateTime:g} · Updated {incident.UpdatedAt.LocalDateTime:g}", 12, "MutedBrush"));
        var links = Ui.Toolbar();
        foreach (var finding in related) links.Children.Add(Ui.Button($"Finding: {finding.Title}", () => OpenFinding(finding.Id)));
        foreach (var asset in Snapshot.Assets.Where(a => assets.Contains(a.Id))) links.Children.Add(Ui.Button($"Asset: {asset.Name}", () => OpenAsset(asset.Id)));
        body.Children.Add(links);
        var detail = new StackPanel();
        detail.Children.Add(Ui.Text("Related security events", 17, bold: true));
        var events = Snapshot.Changes.Where(c => incident.FindingIds.Contains(c.EntityId) || assets.Contains(c.EntityId)).OrderByDescending(c => c.At).Take(12).ToList();
        foreach (var change in events) detail.Children.Add(Ui.Stack(Ui.Text(change.Summary, 14), Ui.Text($"{change.At.LocalDateTime:g} · {change.Kind} · Source: {change.Source}", 12, "MutedBrush")));
        if (events.Count == 0) detail.Children.Add(Ui.Text("No retained security events reference these findings or assets.", 12, "MutedBrush"));
        detail.Children.Add(Ui.Text("Investigation updates", 17, bold: true));
        foreach (var entry in incident.Notes.OrderByDescending(n => n.At).Take(12)) detail.Children.Add(Ui.Stack(Ui.Text(entry.Summary, 14), Ui.Text($"{entry.At.LocalDateTime:g} · {entry.Source}", 12, "MutedBrush")));
        var state = Ui.Select(new[] { "Open", "Investigating", "Contained", "Resolved" }, incident.Status);
        AutomationProperties.SetName(state, "Investigation status");
        var owner = Ui.Input(incident.Owner, 260); AutomationProperties.SetName(owner, "Investigation update owner");
        var note = Ui.Input(); note.MaxLength = 4096; AutomationProperties.SetName(note, "Investigation update note");
        detail.Children.Add(Ui.Toolbar(state, owner)); detail.Children.Add(Ui.Text("Evidence or reason for this update (required)", 12, "MutedBrush")); detail.Children.Add(note);
        detail.Children.Add(Ui.Button("Save investigation update", () => _ = GuardAsync(async () =>
        {
            await _coordinator.UpdateIncidentAsync(incident.Id, state.SelectedItem?.ToString() ?? "Open", owner.Text, note.Text);
            RenderPage(); ShowNotice("Investigation updated", "The owner, status, and update note were audited. No remote action was performed.");
        }), true));
        body.Children.Add(new Expander { Header = "Timeline and investigation workflow", Content = detail });
        return Ui.Card(body);
    }

    private void RenderAnalyst()
    {
        var environmentId = Snapshot.Id;
        if (!_analystConversations.TryGetValue(environmentId, out var conversation))
            _analystConversations[environmentId] = conversation = [];
        PageContent.Children.Add(Ui.Card(Ui.Stack(Ui.Toolbar(Ui.Badge("OFFLINE EVIDENCE ANALYST", "AccentBrush"), Ui.Badge("No external AI connected", "MutedBrush")),
            Ui.Text("Ask a question. Follow the evidence.", 22, bold: true),
            Ui.Text("Answers use collected records and the existing risk engines. Model interpretations are shown as inference. Source confidence describes the evidence, not a probability that an answer is correct. Conversation history stays in this session and is isolated by environment.", brush: "MutedBrush"))));
        var thread = new StackPanel();
        AutomationProperties.SetName(thread, "Analyst conversation history");
        void DrawConversation()
        {
            thread.Children.Clear();
            foreach (var turn in conversation.TakeLast(12)) thread.Children.Add(BuildAnalystTurn(turn));
            if (conversation.Count == 0) thread.Children.Add(Ui.Card(Ui.Stack(Ui.Text("Start with the decision you need to make", 18, bold: true),
                Ui.Text("Ask about priorities, score changes, exposed assets, defensive paths, or a finding by ID. The analyst cites only records present in this environment.", brush: "MutedBrush"))));
        }
        var question = Ui.Input("What should we fix first?"); question.MaxLength = 4096;
        AutomationProperties.SetName(question, "Question");
        question.ToolTip = "Ask the local evidence analyst about this environment";
        var progress = Ui.Text("Ready · no network access required", 12, "MutedBrush");
        Button? ask = null;
        async Task AskAsync(string prompt)
        {
            if (string.IsNullOrWhiteSpace(prompt)) throw new ArgumentException("Enter an analyst question.");
            if (ask is not null && !ask.IsEnabled) return;
            if (ask is not null) ask.IsEnabled = false;
            question.Text = prompt; progress.Text = "Reading evidence and calculating context…";
            try
            {
                var copy = CloneResponseSnapshot(Snapshot);
                var answer = await Task.Run(() => new EvidenceAnalyst().Answer(copy, prompt));
                conversation.Add(new(prompt, answer, DateTimeOffset.UtcNow, copy));
                if (_route == "AI Analyst" && Snapshot.Id == environmentId)
                {
                    DrawConversation();
                    progress.Text = "Answer ready · evidence references checked · inference labeled";
                }
            }
            finally { if (ask is not null) ask.IsEnabled = true; }
        }
        ask = Ui.Button("Ask analyst", () => _ = GuardAsync(() => AskAsync(question.Text)), true);
        AutomationProperties.SetName(ask, "Ask analyst");
        question.KeyDown += (_, e) =>
        {
            if (e.Key != System.Windows.Input.Key.Enter) return;
            e.Handled = true; _ = GuardAsync(() => AskAsync(question.Text));
        };
        var suggestions = Ui.Toolbar();
        foreach (var prompt in new[] { "What should we fix first?", "Why did the security score decrease?", "Which critical assets are most exposed?", "Which remediation removes the most modeled risk?", "What changed since the last assessment?" })
            suggestions.Children.Add(Ui.Button(prompt, () => _ = GuardAsync(() => AskAsync(prompt))));
        PageContent.Children.Add(suggestions);
        PageContent.Children.Add(Ui.Card(Ui.Stack(Ui.Text("Your question", 15, bold: true), question, Ui.Toolbar(ask,
            Ui.Button("Clear conversation", () => { conversation.Clear(); DrawConversation(); })), progress)));
        PageContent.Children.Add(thread); DrawConversation();
    }

    private UIElement BuildAnalystTurn(AnalystTurn turn)
    {
        var nodes = turn.Evidence.Nodes.Where(n => turn.Answer.EvidenceIds.Contains(n.Id)).ToList();
        var findings = turn.Evidence.Findings.Where(f => f.EvidenceIds.Any(turn.Answer.EvidenceIds.Contains)).ToList();
        var assetIds = findings.SelectMany(f => f.AssetIds).Concat(nodes.Where(n => n.Kind is EvidenceKind.Asset or EvidenceKind.CloudResource).Select(n => n.Properties.GetValueOrDefault("assetId") ?? n.Id)).ToHashSet(StringComparer.Ordinal);
        var body = Ui.Stack(Ui.Toolbar(Ui.Badge("YOU", "MutedBrush"), Ui.Text(turn.At.LocalDateTime.ToString("g"), 12, "MutedBrush")),
            Ui.Text(turn.Question, 17, bold: true), Ui.Toolbar(Ui.Badge("ANALYST RESPONSE", "AccentBrush"), Ui.Badge(turn.Answer.UsedAi ? "AI interpretation" : "Local evidence rules", "MutedBrush")));
        var prose = turn.Answer.Answer.Split("Evidence references:", StringSplitOptions.None)[0].Split("Model interpretation:", StringSplitOptions.None)[0].Trim();
        body.Children.Add(Ui.Text(prose, 14));
        body.Children.Add(Ui.Text("INFERENCE · modeled context and limitations", 15, "HighBrush", true));
        body.Children.Add(Ui.Text(turn.Answer.Inferences.Count == 0 ? "No additional inference supplied. The local rules cannot answer questions unsupported by the current records." : string.Join(Environment.NewLine, turn.Answer.Inferences), 14, "MutedBrush"));
        body.Children.Add(Ui.Text("EVIDENCE · collected source records", 15, "AccentBrush", true));
        body.Children.Add(Ui.Text(nodes.Count == 0 ? "Confidence: unavailable · no supporting evidence nodes were cited." :
            $"Confidence of cited source records: {nodes.Min(n => n.Confidence):P0}–{nodes.Max(n => n.Confidence):P0}. Answer confidence is not independently calibrated.", 12, "MutedBrush"));
        foreach (var node in nodes.Take(8))
        {
            var source = Ui.Stack(Ui.Text($"{node.Label} · {node.Kind}", 14, bold: true),
                Ui.Text($"Source: {node.Source} · Observed {node.ObservedAt.LocalDateTime:g} · Confidence {node.Confidence:P0}", 12, "MutedBrush"));
            if (Snapshot.Nodes.Any(n => n.Id == node.Id)) source.Children.Add(Ui.Button("Open supporting evidence", () => OpenEvidence(node.Id)));
            body.Children.Add(source);
        }
        if (nodes.Count > 8) body.Children.Add(Ui.Text($"{nodes.Count - 8} additional cited records are available in the related evidence graph.", 12, "MutedBrush"));
        var links = Ui.Toolbar();
        foreach (var finding in findings.Take(6))
            if (Snapshot.Findings.Any(f => f.Id == finding.Id)) links.Children.Add(Ui.Button($"Finding: {finding.Title}", () => OpenFinding(finding.Id)));
        foreach (var asset in turn.Evidence.Assets.Where(a => assetIds.Contains(a.Id)).Take(6))
            if (Snapshot.Assets.Any(a => a.Id == asset.Id)) links.Children.Add(Ui.Button($"Asset: {asset.Name}", () => OpenAsset(asset.Id)));
        body.Children.Add(links);
        if (findings.Count > 0) body.Children.Add(Ui.Button("Review prioritized remediation", () => Navigate("Remediation")));
        return Ui.Card(body);
    }

    private void RenderReports()
    {
        var environmentId = Snapshot.Id;
        var types = Enum.GetValues<ReportKind>().Select(k => new ReportType(k, ResponseReportTitle(k))).ToList();
        var type = new ComboBox { ItemsSource = types, DisplayMemberPath = "Title", SelectedIndex = 0, MinWidth = 260 };
        AutomationProperties.SetName(type, "Report types");
        var scope = Ui.Select(new[] { "Entire environment", "Critical assets", "Endpoints", "Servers", "Network devices", "Cloud resources", "Web applications" }, "Entire environment");
        AutomationProperties.SetName(scope, "Report scope");
        var format = Ui.Select(Enum.GetValues<ReportFormat>(), ReportFormat.Pdf);
        AutomationProperties.SetName(format, "Report export format");
        var history = Ui.Select(new[] { "All retained history", "Last 7 days", "Last 30 days", "Last 90 days", "Custom date range" }, "All retained history");
        AutomationProperties.SetName(history, "Report history date range");
        var from = new DatePicker { SelectedDate = DateTime.Today.AddDays(-30), IsEnabled = false, Width = 160, Margin = new Thickness(0, 0, 8, 12) };
        var to = new DatePicker { SelectedDate = DateTime.Today, IsEnabled = false, Width = 160, Margin = new Thickness(0, 0, 8, 12) };
        AutomationProperties.SetName(from, "Report history start date"); AutomationProperties.SetName(to, "Report history end date");
        var preview = new StackPanel(); AutomationProperties.SetName(preview, "Report Preview");
        var result = Ui.Text("Choose a report and review its evidence-derived preview before export.", 12, "MutedBrush");
        var status = Ui.Text("Report preview is ready to generate.", 12, "MutedBrush");
        var inclusion = Ui.Stack(Ui.Text("Included by this report template", 15, bold: true));
        void Inclusion(string label, bool enabled, string reason)
        {
            var check = new CheckBox { Content = label, IsChecked = enabled, IsEnabled = false, ToolTip = reason, Margin = new Thickness(0, 0, 0, 8) };
            AutomationProperties.SetName(check, label); inclusion.Children.Add(check);
        }
        void UpdateInclusions()
        {
            while (inclusion.Children.Count > 1) inclusion.Children.RemoveAt(1);
            var kind = ((ReportType)type.SelectedItem).Kind;
            Inclusion("Charts", false, "Chart export is not supported by the existing reporting engine. The preview and export use evidence tables and narratives.");
            Inclusion("Attack paths", kind is ReportKind.Executive or ReportKind.Technical or ReportKind.Remediation, "Sections follow the selected engine template and cannot be independently toggled.");
            Inclusion("Asset details", kind is ReportKind.Technical or ReportKind.AssetInventory, "Sections follow the selected engine template and cannot be independently toggled.");
            Inclusion("Remediation", kind is not (ReportKind.AssetInventory or ReportKind.SecurityProgress), "Sections follow the selected engine template and cannot be independently toggled.");
            Inclusion("Confidence and limitations", true, "Evidence confidence and limitations are always retained; they cannot be removed.");
        }

        EnvironmentSnapshot CaptureReportSnapshot()
        {
            if (Snapshot.Id != environmentId) throw new InvalidOperationException("The environment changed. Reopen Report Studio to export its evidence.");
            var selectedRange = history.SelectedItem?.ToString() ?? "All retained history";
            DateTimeOffset? start = selectedRange switch
            {
                "Last 7 days" => DateTimeOffset.UtcNow.AddDays(-7), "Last 30 days" => DateTimeOffset.UtcNow.AddDays(-30),
                "Last 90 days" => DateTimeOffset.UtcNow.AddDays(-90), "Custom date range" => from.SelectedDate is DateTime d ? new DateTimeOffset(d.Date) : throw new ArgumentException("Choose the history start date."), _ => null
            };
            DateTimeOffset? end = selectedRange == "Custom date range" ? to.SelectedDate is DateTime d ? new DateTimeOffset(d.Date.AddDays(1)) : throw new ArgumentException("Choose the history end date.") : null;
            if (start.HasValue && end.HasValue && end <= start) throw new ArgumentException("The report end date must be on or after its start date.");
            return BuildResponseReportSnapshot(Snapshot, scope.SelectedItem?.ToString() ?? "Entire environment", start, end);
        }

        var revision = 0;
        async Task PreviewAsync()
        {
            var request = ++revision;
            var copy = CaptureReportSnapshot();
            var selected = ((ReportType)type.SelectedItem).Kind;
            status.Text = "Generating preview from the selected evidence…";
            var directory = Path.Combine(_dataDirectory, "ReportPreviews");
            var path = Path.Combine(directory, Guid.NewGuid().ToString("N") + ".json");
            try
            {
                await new ReportingEngine().ExportAsync(copy, selected, ReportFormat.Json, path);
                await using var stream = File.OpenRead(path);
                using var document = await JsonDocument.ParseAsync(stream);
                if (request != revision || _route != "Reports" || Snapshot.Id != environmentId) return;
                preview.Children.Clear();
                var report = document.RootElement;
                preview.Children.Add(Ui.Text(report.GetProperty("Title").GetString() ?? "Report", 21, bold: true));
                preview.Children.Add(Ui.Text($"{copy.Name} · {copy.Mode} · {copy.Assets.Count} assets · {copy.Findings.Count} findings", 12, "MutedBrush"));
                preview.Children.Add(Ui.Text(report.GetProperty("Disclaimer").GetString() ?? "", 12, "HighBrush"));
                foreach (var section in report.GetProperty("Sections").EnumerateArray())
                {
                    preview.Children.Add(Ui.Text(section.GetProperty("Title").GetString() ?? "Section", 17, bold: true));
                    foreach (var paragraph in section.GetProperty("Paragraphs").EnumerateArray().Take(2)) preview.Children.Add(Ui.Text(paragraph.GetString() ?? "", 12, "MutedBrush"));
                    foreach (var table in section.GetProperty("Tables").EnumerateArray())
                    {
                        var rows = table.GetProperty("Rows");
                        preview.Children.Add(Ui.Text($"{rows.GetArrayLength()} evidence rows · {string.Join(" · ", table.GetProperty("Columns").EnumerateArray().Select(c => c.GetString()))}", 12, "MutedBrush"));
                        foreach (var row in rows.EnumerateArray().Take(2)) preview.Children.Add(Ui.Text(string.Join(" · ", row.EnumerateArray().Select(c => c.GetString())), 12));
                    }
                }
                status.Text = "Preview generated by the reporting engine · no evidence changed";
            }
            finally { if (File.Exists(path)) File.Delete(path); }
        }

        var export = Ui.Button("Export report", () => _ = GuardAsync(async () =>
        {
            var selected = ((ReportType)type.SelectedItem).Kind;
            var selectedFormat = (ReportFormat)format.SelectedItem;
            var extension = selectedFormat.ToString().ToLowerInvariant();
            var copy = CaptureReportSnapshot();
            var dialog = new SaveFileDialog { FileName = $"SENTINEL-{selected}-{DateTime.Today:yyyy-MM-dd}.{extension}", Filter = $"{selectedFormat} report|*.{extension}", AddExtension = true, DefaultExt = extension, OverwritePrompt = true };
            if (dialog.ShowDialog(this) != true) return;
            result.Text = "Exporting report…";
            var artifact = await new ReportingEngine().ExportAsync(copy, selected, selectedFormat, dialog.FileName);
            await _repository.AuditAsync(new(DateTimeOffset.UtcNow, "report.exported", copy.Id,
                $"{selected}; {selectedFormat}; scope={scope.SelectedItem}; history={history.SelectedItem}; {copy.Assets.Count} scoped assets", Guid.NewGuid().ToString("N")[..12]));
            result.Text = $"Report saved: {artifact.Path}";
            ShowNotice("Report exported", $"{ResponseReportTitle(selected)} · {artifact.Format} · {artifact.CreatedAt.LocalDateTime:g}");
        }), true);
        var configuration = Ui.Stack(Ui.Text("REPORT STUDIO", 12, "AccentBrush", true), Ui.Text("Report configuration", 21, bold: true),
            Ui.Text("Report type", 12, "MutedBrush"), type, Ui.Text("Scope", 12, "MutedBrush"), scope,
            Ui.Text($"Environment: {Snapshot.Name} · {Snapshot.Mode}", 12, "MutedBrush"),
            Ui.Text("History date range", 12, "MutedBrush"), history, Ui.Toolbar(from, to),
            Ui.Text("The date range filters retained timeline, scores, scans, and observations. Current posture remains the latest collected snapshot; this does not reconstruct historical posture.", 12, "MutedBrush"),
            inclusion, Ui.Text("Export format", 12, "MutedBrush"), format, Ui.Toolbar(export, Ui.Button("Refresh preview", () => _ = GuardAsync(PreviewAsync))), result);
        PageContent.Children.Add(Ui.Columns(Ui.Card(configuration), Ui.Card(Ui.Stack(Ui.Text("Report Preview", 21, bold: true), status, preview))));
        if (Snapshot.Assets.Count == 0 && Snapshot.Findings.Count == 0) PageContent.Children.Add(Ui.Card(Ui.Stack(Ui.Text("No collected report evidence", 18, bold: true), Ui.Text("You can export the current scope and limitations; the report will not imply that unassessed assets are secure.", brush: "MutedBrush"))));
        type.SelectionChanged += (_, _) => { UpdateInclusions(); _ = GuardAsync(PreviewAsync); };
        scope.SelectionChanged += (_, _) => _ = GuardAsync(PreviewAsync);
        history.SelectionChanged += (_, _) => { from.IsEnabled = to.IsEnabled = history.SelectedItem?.ToString() == "Custom date range"; _ = GuardAsync(PreviewAsync); };
        from.SelectedDateChanged += (_, _) => _ = GuardAsync(PreviewAsync);
        to.SelectedDateChanged += (_, _) => _ = GuardAsync(PreviewAsync);
        UpdateInclusions(); _ = GuardAsync(PreviewAsync);
    }

    internal static EnvironmentSnapshot BuildResponseReportSnapshot(EnvironmentSnapshot snapshot, string scope, DateTimeOffset? start, DateTimeOffset? end)
    {
        var copy = CloneResponseSnapshot(snapshot);
        bool Within(DateTimeOffset at) => (!start.HasValue || at >= start) && (!end.HasValue || at < end);
        copy.ScoreHistory.RemoveAll(h => !Within(h.At));
        copy.Changes.RemoveAll(c => !Within(c.At));
        copy.Scans.RemoveAll(s => !Within(s.StartedAt));
        copy.Observations.RemoveAll(o => !Within(o.ObservedAt));
        if (scope == "Entire environment") return copy;
        var selectedAssets = copy.Assets.Where(a => scope switch
        {
            "Critical assets" => a.IsCritical, "Endpoints" => a.Kind == AssetKind.Endpoint, "Servers" => a.Kind == AssetKind.Server,
            "Network devices" => a.Kind == AssetKind.NetworkDevice, "Cloud resources" => a.Kind == AssetKind.CloudResource, "Web applications" => a.Kind == AssetKind.WebApplication,
            _ => throw new ArgumentException("Choose a supported report scope.")
        }).Select(a => a.Id).ToHashSet(StringComparer.Ordinal);
        copy.Name += $" · scoped to {scope.ToLowerInvariant()} (latest evidence)";
        var excludedAssets = copy.Assets.Where(a => !selectedAssets.Contains(a.Id)).Select(a => a.Id).ToHashSet(StringComparer.Ordinal);
        copy.Assets.RemoveAll(a => !selectedAssets.Contains(a.Id));
        copy.Findings.RemoveAll(f => !f.AssetIds.Any(selectedAssets.Contains));
        foreach (var finding in copy.Findings) finding.AssetIds.RemoveAll(id => !selectedAssets.Contains(id));
        var findingIds = copy.Findings.Select(f => f.Id).ToHashSet(StringComparer.Ordinal);
        var nodes = selectedAssets.Concat(copy.Findings.SelectMany(f => f.EvidenceIds)).Concat(findingIds).ToHashSet(StringComparer.Ordinal);
        // Keep a bounded, connected evidence context, excluding assets outside scope.
        // Recomputing the graph's paths from this subset cannot imply full coverage.
        for (var depth = 0; depth < 2; depth++)
            foreach (var edge in copy.Edges.Where(e => nodes.Contains(e.SourceId) || nodes.Contains(e.TargetId)).ToArray())
            {
                if (!excludedAssets.Contains(edge.SourceId)) nodes.Add(edge.SourceId);
                if (!excludedAssets.Contains(edge.TargetId)) nodes.Add(edge.TargetId);
            }
        copy.Nodes.RemoveAll(n => !nodes.Contains(n.Id) || excludedAssets.Contains(n.Id) ||
            (n.Properties.TryGetValue("assetId", out var assetId) && !selectedAssets.Contains(assetId)));
        nodes = copy.Nodes.Select(n => n.Id).ToHashSet(StringComparer.Ordinal);
        copy.Edges.RemoveAll(e => !nodes.Contains(e.SourceId) || !nodes.Contains(e.TargetId));
        foreach (var edge in copy.Edges) edge.FindingIds.RemoveAll(id => !findingIds.Contains(id));
        foreach (var finding in copy.Findings) finding.EvidenceIds.RemoveAll(id => !nodes.Contains(id));
        copy.Identities.RemoveAll(i => !nodes.Contains(i.Id));
        copy.Certificates.RemoveAll(c => !selectedAssets.Contains(c.AssetId));
        copy.Observations.RemoveAll(o => !selectedAssets.Contains(o.AssetId));
        copy.Changes.RemoveAll(c => !selectedAssets.Contains(c.EntityId) && !findingIds.Contains(c.EntityId) && !nodes.Contains(c.EntityId));
        copy.Incidents.RemoveAll(i => !i.FindingIds.Any(findingIds.Contains));
        foreach (var incident in copy.Incidents) incident.FindingIds.RemoveAll(id => !findingIds.Contains(id));
        // Environment-level history cannot safely be relabeled as a scoped score or
        // scope-specific assessment. Preserve it only in Entire environment reports.
        copy.ScoreHistory.Clear(); copy.Scans.Clear();
        return copy;
    }

    private static EnvironmentSnapshot CloneResponseSnapshot(EnvironmentSnapshot snapshot)
        => JsonSerializer.Deserialize<EnvironmentSnapshot>(JsonSerializer.Serialize(snapshot))!;

    private static string ResponseReportTitle(ReportKind kind) => kind switch
    {
        ReportKind.Executive => "Executive Security Report", ReportKind.Technical => "Technical Assessment Report",
        ReportKind.Vulnerability => "Vulnerability Report", ReportKind.AssetInventory => "Asset Inventory",
        ReportKind.Remediation => "Remediation Report", ReportKind.Compliance => "Compliance Report", _ => "Security Progress Report"
    };

    private sealed record ReportType(ReportKind Kind, string Title);
    private sealed record AnalystTurn(string Question, AnalystAnswer Answer, DateTimeOffset At, EnvironmentSnapshot Evidence);
}
