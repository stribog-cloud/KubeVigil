package report

import (
	"html"
	"regexp"
	"strings"
)

// codeBlockRe matches markdown fenced code blocks (``` with optional lang).
var codeBlockRe = regexp.MustCompile("(?s)```(\\w*)\\n(.*?)```")

// formatRemediationBody converts a remediation string containing markdown-style
// fenced code blocks into inner HTML content (paragraphs and code blocks)
// without a wrapper element. Returns empty string for empty input.
func formatRemediationBody(text string) string {
	if text == "" {
		return ""
	}

	var b strings.Builder
	lastIdx := 0
	for _, loc := range codeBlockRe.FindAllStringIndex(text, -1) {
		// Write prose before this code block.
		prose := text[lastIdx:loc[0]]
		writeProseHTML(&b, prose)

		// Extract language and code from the match.
		match := codeBlockRe.FindStringSubmatch(text[loc[0]:loc[1]])
		lang := match[1]
		code := match[2]

		// Remove trailing newline from code if present.
		code = strings.TrimRight(code, "\n")

		cls := "code-block"
		if lang != "" {
			cls += " language-" + html.EscapeString(lang)
		}
		b.WriteString(`<pre class="` + cls + `"><code>`)
		b.WriteString(html.EscapeString(code))
		b.WriteString("</code></pre>")

		lastIdx = loc[1]
	}

	// Write any remaining prose after the last code block.
	if lastIdx < len(text) {
		writeProseHTML(&b, text[lastIdx:])
	}

	return b.String()
}

// formatRemediationHTML converts a remediation string to HTML wrapped in a
// collapsible <details> element. Delegates to formatRemediationBody for the
// inner content.
func formatRemediationHTML(text string) string {
	body := formatRemediationBody(text)
	if body == "" {
		return ""
	}
	return `<details class="remediation"><summary>Show Fix</summary><div class="rem-body">` + body + `</div></details>`
}

// writeProseHTML writes prose text with paragraph, header, and line-break handling.
// Markdown headers (## and ###) that occupy an entire paragraph are rendered as
// <h3 class="rem-h3"> and <h4 class="rem-h4"> respectively. All header text is
// HTML-escaped to prevent XSS.
func writeProseHTML(b *strings.Builder, prose string) {
	prose = strings.TrimSpace(prose)
	if prose == "" {
		return
	}

	// Split on double newlines for paragraphs.
	paragraphs := strings.Split(prose, "\n\n")
	for _, p := range paragraphs {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}

		// Check for markdown headers (entire paragraph is a single header line).
		if strings.HasPrefix(p, "### ") && !strings.Contains(p, "\n") {
			title := strings.TrimSpace(p[4:])
			b.WriteString(`<h4 class="rem-h4">`)
			b.WriteString(html.EscapeString(title))
			b.WriteString("</h4>")
			continue
		}
		if strings.HasPrefix(p, "## ") && !strings.Contains(p, "\n") {
			title := strings.TrimSpace(p[3:])
			b.WriteString(`<h3 class="rem-h3">`)
			b.WriteString(html.EscapeString(title))
			b.WriteString("</h3>")
			continue
		}

		b.WriteString("<p>")
		// Single newlines within a paragraph become <br>.
		lines := strings.Split(p, "\n")
		for i, line := range lines {
			b.WriteString(html.EscapeString(strings.TrimSpace(line)))
			if i < len(lines)-1 {
				b.WriteString("<br>")
			}
		}
		b.WriteString("</p>")
	}
}
