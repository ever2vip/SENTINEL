using System.Globalization;
using System.Text;

namespace Sentinel.Infrastructure;

/// <summary>A self-contained, paginated PDF 1.4 writer using standard Helvetica fonts.</summary>
internal static class SimplePdfWriter
{
    public static byte[] Create(ReportDocument document, CancellationToken cancellationToken)
    {
        var layout = new Layout(document, cancellationToken);
        layout.Paragraph(document.Disclaimer, 10, true);
        layout.Paragraph("PDF uses Western-European standard fonts. JSON, CSV and HTML preserve names outside that character set.", 8);
        layout.Space(10);
        foreach (var section in document.Sections)
        {
            cancellationToken.ThrowIfCancellationRequested();
            layout.SectionTitle(section.Title);
            foreach (var paragraph in section.Paragraphs) layout.Paragraph(paragraph);
            foreach (var table in section.Tables) layout.Table(table);
        }
        return Assemble(document, layout.Pages, cancellationToken);
    }

    private static byte[] Assemble(ReportDocument document, IReadOnlyList<StringBuilder> pages, CancellationToken token)
    {
        var objects = new List<byte[]>();
        static byte[] A(string value) => Encoding.ASCII.GetBytes(value);
        objects.Add(A("<< /Type /Catalog /Pages 2 0 R >>"));
        var kids = string.Join(" ", Enumerable.Range(0, pages.Count).Select(i => $"{6 + i * 2} 0 R"));
        objects.Add(A($"<< /Type /Pages /Count {pages.Count} /Kids [ {kids} ] >>"));
        objects.Add(A("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>"));
        objects.Add(A("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>"));
        objects.Add(A($"<< /Title {MetadataLiteral(document.Title)} /Author {MetadataLiteral("SENTINEL Enterprise")} /Subject {MetadataLiteral(document.EnvironmentName + " — " + document.ReportId)} /Creator {MetadataLiteral("SENTINEL local reporting engine")} /CreationDate {Literal(document.GeneratedAt.ToUniversalTime().ToString("'D:'yyyyMMddHHmmss'Z'", CultureInfo.InvariantCulture))} >>"));
        for (var i = 0; i < pages.Count; i++)
        {
            token.ThrowIfCancellationRequested();
            var contentId = 7 + i * 2;
            var pageContent = pages[i].ToString() + Footer(document, i + 1, pages.Count);
            var content = A(pageContent);
            objects.Add(A($"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595.28 841.89] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents {contentId} 0 R >>"));
            using var streamObject = new MemoryStream();
            streamObject.Write(A($"<< /Length {content.Length} >>\nstream\n"));
            streamObject.Write(content);
            streamObject.Write(A("\nendstream"));
            objects.Add(streamObject.ToArray());
        }
        using var output = new MemoryStream();
        output.Write(A("%PDF-1.4\n%SENTINEL\n"));
        var offsets = new List<long>();
        for (var i = 0; i < objects.Count; i++)
        {
            token.ThrowIfCancellationRequested();
            offsets.Add(output.Position);
            output.Write(A($"{i + 1} 0 obj\n"));
            output.Write(objects[i]);
            output.Write(A("\nendobj\n"));
        }
        var xrefOffset = output.Position;
        output.Write(A($"xref\n0 {objects.Count + 1}\n0000000000 65535 f \n"));
        foreach (var offset in offsets) output.Write(A(offset.ToString("D10", CultureInfo.InvariantCulture) + " 00000 n \n"));
        output.Write(A($"trailer\n<< /Size {objects.Count + 1} /Root 1 0 R /Info 5 0 R >>\nstartxref\n{xrefOffset}\n%%EOF\n"));
        return output.ToArray();
    }

    private static string Footer(ReportDocument report, int number, int count)
    {
        var output = new StringBuilder();
        output.Append("0.82 0.86 0.91 RG 0.5 w 44 51 m 551 51 l S\n");
        Text(output, 44, 34, 8, "SENTINEL · " + report.ReportId, false, "0.36 0.41 0.49");
        Text(output, 461, 34, 8, $"Page {number} of {count}", false, "0.36 0.41 0.49");
        return output.ToString();
    }

    private sealed class Layout
    {
        private readonly ReportDocument _report;
        private readonly CancellationToken _token;
        private double _y;
        private StringBuilder _page = new();
        public List<StringBuilder> Pages { get; } = [];
        private const double Left = 44;
        private const double Width = 507;
        private const double Bottom = 70;

        public Layout(ReportDocument report, CancellationToken token)
        {
            _report = report;
            _token = token;
            NewPage();
        }

        private void NewPage()
        {
            _token.ThrowIfCancellationRequested();
            _page = new StringBuilder();
            Pages.Add(_page);
            _page.Append("0.07 0.19 0.32 rg 0 777 595.28 64 re f\n");
            Text(_page, Left, 813, 11, "SENTINEL ENTERPRISE", true, "1 1 1");
            Text(_page, Left, 791, 9, Clip(_report.Title, Width, 9), false, "0.83 0.9 0.98");
            Text(_page, Left, 759, 9, Clip(_report.EnvironmentName + " · " + _report.EnvironmentMode + " · " + _report.GeneratedAt.ToUniversalTime().ToString("yyyy-MM-dd HH:mm 'UTC'", CultureInfo.InvariantCulture), Width, 9), false, "0.35 0.4 0.48");
            _y = 735;
        }

        public void Space(double height)
        {
            if (_y - height < Bottom) NewPage();
            else _y -= height;
        }

        public void SectionTitle(string title)
        {
            var lines = Wrap(title, Width, 14).ToArray();
            Ensure(18 * lines.Length + 46);
            _y -= 12;
            foreach (var line in lines)
            {
                Text(_page, Left, _y, 14, line, true, "0.07 0.22 0.38");
                _y -= 18;
            }
            _page.Append("0.72 0.8 0.88 RG 0.7 w ").Append(N(Left)).Append(' ').Append(N(_y + 4)).Append(" m 551 ").Append(N(_y + 4)).Append(" l S\n");
            _y -= 12;
        }

        public void Paragraph(string text, double size = 10, bool bold = false)
        {
            var lines = Wrap(text, Width, size).ToArray();
            var spacing = size * 1.4;
            // Keep short paragraphs together and avoid a lone opening line at a page boundary.
            Ensure(Math.Min(lines.Length, lines.Length <= 4 ? 4 : 2) * spacing);
            foreach (var line in lines)
            {
                _token.ThrowIfCancellationRequested();
                Ensure(spacing);
                Text(_page, Left, _y, size, line, bold, "0.12 0.17 0.23");
                _y -= spacing;
            }
            Space(7);
        }

        public void Table(ReportTable table)
        {
            if (table.Rows.Count == 0) return;
            if (table.Columns.Count <= 4 && table.Columns.All(c => c.Length <= 80) && table.Rows.All(r => r.All(c => c.Length <= 110)))
            {
                Grid(table);
                return;
            }
            // Field-oriented rows keep wide technical tables readable on a portrait page.
            // Rows and long fields flow across pages rather than being clipped or shrunk.
            for (var rowIndex = 0; rowIndex < table.Rows.Count; rowIndex++)
            {
                _token.ThrowIfCancellationRequested();
                Ensure(48);
                _page.Append("0.93 0.96 0.99 rg 44 ").Append(N(_y - 5)).Append(" 507 18 re f\n");
                Text(_page, Left + 6, _y, 9, "Record " + (rowIndex + 1).ToString(CultureInfo.InvariantCulture), true, "0.08 0.22 0.37");
                _y -= 22;
                for (var column = 0; column < table.Columns.Count; column++)
                {
                    var text = table.Columns[column] + ": " + (string.IsNullOrEmpty(table.Rows[rowIndex][column]) ? "—" : table.Rows[rowIndex][column]);
                    var firstLine = true;
                    foreach (var line in Wrap(text, Width - 12, 9))
                    {
                        Ensure(12.5);
                        Text(_page, Left + 6, _y, 9, line, firstLine && table.Columns.Count <= 2, "0.15 0.19 0.25");
                        _y -= 12.5;
                        firstLine = false;
                    }
                }
                Space(11);
            }
            Space(6);
        }

        private void Grid(ReportTable table)
        {
            const double size = 8.5;
            var columnWidth = Width / table.Columns.Count;
            string[][] Lines(IReadOnlyList<string> cells) => cells.Select(c => Wrap(string.IsNullOrEmpty(c) ? "—" : c, columnWidth - 12, size).ToArray()).ToArray();
            static double Height(string[][] cells) => cells.Max(c => c.Length) * 12 + 10;
            var headers = Lines(table.Columns);
            var headerHeight = Height(headers);
            void Draw(string[][] cells, bool header, bool alternate)
            {
                var height = Height(cells);
                if (header || alternate)
                    _page.Append(header ? "0.89 0.93 0.98 rg " : "0.97 0.98 0.99 rg ")
                        .Append(N(Left)).Append(' ').Append(N(_y - height)).Append(' ').Append(N(Width)).Append(' ').Append(N(height)).Append(" re f\n");
                _page.Append("0.82 0.86 0.91 RG 0.4 w ").Append(N(Left)).Append(' ').Append(N(_y - height))
                    .Append(' ').Append(N(Width)).Append(' ').Append(N(height)).Append(" re S\n");
                for (var c = 0; c < cells.Length; c++)
                {
                    for (var l = 0; l < cells[c].Length; l++)
                        Text(_page, Left + c * columnWidth + 6, _y - 13 - l * 12, size, cells[c][l], header, "0.12 0.2 0.29");
                    if (c > 0)
                        _page.Append("0.82 0.86 0.91 RG 0.4 w ").Append(N(Left + c * columnWidth)).Append(' ').Append(N(_y))
                            .Append(" m ").Append(N(Left + c * columnWidth)).Append(' ').Append(N(_y - height)).Append(" l S\n");
                }
                _y -= height;
            }
            Ensure(headerHeight + Height(Lines(table.Rows[0])));
            Draw(headers, true, false);
            for (var row = 0; row < table.Rows.Count; row++)
            {
                _token.ThrowIfCancellationRequested();
                var lines = Lines(table.Rows[row]);
                if (_y - Height(lines) < Bottom)
                {
                    NewPage();
                    Draw(headers, true, false);
                }
                Draw(lines, false, row % 2 == 1);
            }
            Space(10);
        }

        private void Ensure(double height) { if (_y - height < Bottom) NewPage(); }
    }

    private static void Text(StringBuilder output, double x, double y, double size, string value, bool bold, string color)
    {
        output.Append("BT ").Append(color).Append(" rg /").Append(bold ? "F2" : "F1").Append(' ').Append(N(size))
            .Append(" Tf 1 0 0 1 ").Append(N(x)).Append(' ').Append(N(y)).Append(" Tm ").Append(Literal(value)).Append(" Tj ET\n");
    }

    private static string N(double value) => value.ToString("0.##", CultureInfo.InvariantCulture);

    private static IEnumerable<string> Wrap(string value, double width, double size)
    {
        // Normalize controls before wrapping; escaped PDF text is never interpreted as operators.
        value = Normalize(value);
        foreach (var paragraph in value.Replace("\r", "", StringComparison.Ordinal).Split('\n'))
        {
            if (paragraph.Length == 0) { yield return ""; continue; }
            var line = new StringBuilder();
            double used = 0;
            foreach (var word in paragraph.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            {
                var wordWidth = Measure(word, size);
                if (line.Length > 0 && used + Measure(" ", size) + wordWidth > width)
                {
                    yield return line.ToString();
                    line.Clear();
                    used = 0;
                }
                if (wordWidth > width)
                {
                    foreach (var character in word)
                    {
                        var characterWidth = Measure(character.ToString(), size);
                        if (used + characterWidth > width && line.Length > 0)
                        {
                            yield return line.ToString();
                            line.Clear();
                            used = 0;
                        }
                        line.Append(character);
                        used += characterWidth;
                    }
                }
                else
                {
                    if (line.Length > 0) { line.Append(' '); used += Measure(" ", size); }
                    line.Append(word);
                    used += wordWidth;
                }
            }
            if (line.Length > 0) yield return line.ToString();
        }
    }

    private static string Clip(string value, double width, double size)
    {
        value = Normalize(value).Replace('\n', ' ').Replace('\r', ' ');
        if (Measure(value, size) <= width) return value;
        while (value.Length > 0 && Measure(value + "...", size) > width) value = value[..^1];
        return value + "...";
    }

    private static double Measure(string value, double size)
    {
        double sum = 0;
        foreach (var c in value)
            sum += c switch
            {
                'i' or 'l' or 'I' or '.' or ',' or ':' or ';' or '!' or '|' or '\'' => 0.28,
                ' ' or '(' or ')' or '[' or ']' or '{' or '}' or 't' or 'f' or 'r' => 0.36,
                'm' or 'w' or 'M' or 'W' or '@' => 0.92,
                >= 'A' and <= 'Z' => 0.72,
                _ => 0.59
            };
        return sum * size;
    }

    private static string Normalize(string value)
    {
        var result = new StringBuilder(value.Length);
        foreach (var rune in value.EnumerateRunes())
        {
            if (rune.Value is '\n' or '\r') result.Append((char)rune.Value);
            else if (rune.Value == '\t') result.Append("    ");
            else if (rune.Value == 0x2192) result.Append(" -> ");
            else if (rune.Value < 32 || rune.Value == 127) result.Append(' ');
            else if (WinAnsiByte(rune.Value) >= 0) result.Append(rune.ToString());
            else result.Append('?');
        }
        return result.ToString();
    }

    private static string Literal(string value)
    {
        var output = new StringBuilder("(");
        foreach (var rune in value.EnumerateRunes())
        {
            var b = WinAnsiByte(rune.Value);
            if (b < 0) b = '?';
            if (b is '(' or ')' or '\\') output.Append('\\').Append((char)b);
            else if (b < 32 || b >= 127) output.Append('\\').Append(Convert.ToString(b, 8).PadLeft(3, '0'));
            else output.Append((char)b);
        }
        return output.Append(')').ToString();
    }

    // PDF information dictionaries use PDFDocEncoding rather than the font's WinAnsiEncoding.
    // UTF-16BE hex strings preserve Unicode provenance in metadata without that ambiguity.
    private static string MetadataLiteral(string value) => "<FEFF" + Convert.ToHexString(Encoding.BigEndianUnicode.GetBytes(value)) + ">";

    private static int WinAnsiByte(int codepoint)
    {
        if (codepoint is >= 32 and <= 126 or >= 160 and <= 255) return codepoint;
        return codepoint switch
        {
            0x20AC => 0x80, 0x201A => 0x82, 0x0192 => 0x83, 0x201E => 0x84, 0x2026 => 0x85,
            0x2020 => 0x86, 0x2021 => 0x87, 0x02C6 => 0x88, 0x2030 => 0x89, 0x0160 => 0x8A,
            0x2039 => 0x8B, 0x0152 => 0x8C, 0x017D => 0x8E, 0x2018 => 0x91, 0x2019 => 0x92,
            0x201C => 0x93, 0x201D => 0x94, 0x2022 => 0x95, 0x2013 => 0x96, 0x2014 => 0x97,
            0x02DC => 0x98, 0x2122 => 0x99, 0x0161 => 0x9A, 0x203A => 0x9B, 0x0153 => 0x9C,
            0x017E => 0x9E, 0x0178 => 0x9F, _ => -1
        };
    }
}
