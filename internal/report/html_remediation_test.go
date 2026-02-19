package report

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFormatRemediationBody_Empty(t *testing.T) {
	assert.Equal(t, "", formatRemediationBody(""))
}

func TestFormatRemediationBody_Content(t *testing.T) {
	got := formatRemediationBody("Set privileged to false.")
	assert.Contains(t, got, "<p>Set privileged to false.</p>")
	// Should NOT include the <details> wrapper.
	assert.NotContains(t, got, "<details")
	assert.NotContains(t, got, "</details>")
}

func TestFormatRemediationHTML_Empty(t *testing.T) {
	assert.Equal(t, "", formatRemediationHTML(""))
}

func TestFormatRemediationHTML_ProseOnly(t *testing.T) {
	got := formatRemediationHTML("Set privileged to false.")
	assert.Contains(t, got, "<details")
	assert.Contains(t, got, "Show Fix")
	assert.Contains(t, got, "<p>Set privileged to false.</p>")
	assert.Contains(t, got, "</details>")
}

func TestFormatRemediationHTML_CodeBlock(t *testing.T) {
	input := "Fix it:\n\n```yaml\nspec:\n  hostNetwork: false\n```\n\nDone."
	got := formatRemediationHTML(input)

	assert.Contains(t, got, `<pre class="code-block language-yaml"><code>`)
	assert.Contains(t, got, "spec:\n  hostNetwork: false")
	assert.Contains(t, got, "</code></pre>")
	assert.Contains(t, got, "<p>Fix it:</p>")
	assert.Contains(t, got, "<p>Done.</p>")
}

func TestFormatRemediationHTML_MultipleCodeBlocks(t *testing.T) {
	input := "First block:\n\n```yaml\na: 1\n```\n\nSecond block:\n\n```json\n{\"b\": 2}\n```"
	got := formatRemediationHTML(input)

	assert.Equal(t, 2, strings.Count(got, "<pre class="))
	assert.Contains(t, got, "language-yaml")
	assert.Contains(t, got, "language-json")
}

func TestFormatRemediationHTML_EscapesHTML(t *testing.T) {
	input := "Don't use <script>alert('xss')</script>\n\n```yaml\nkey: <value>\n```"
	got := formatRemediationHTML(input)

	assert.NotContains(t, got, "<script>")
	assert.Contains(t, got, "&lt;script&gt;")
	assert.Contains(t, got, "key: &lt;value&gt;")
}

func TestFormatRemediationHTML_LineBreaks(t *testing.T) {
	input := "Line one\nLine two\n\nNew paragraph"
	got := formatRemediationHTML(input)

	assert.Contains(t, got, "Line one<br>Line two")
	assert.Contains(t, got, "<p>New paragraph</p>")
}

func TestFormatRemediationHTML_RealRemediation(t *testing.T) {
	input := "Container shares the host network namespace, allowing access to all host network interfaces.\n\n" +
		"Fix: Disable host networking in the pod spec:\n\n" +
		"```yaml\nspec:\n  hostNetwork: false\n```\n\n" +
		"Use Services and Ingress to expose pods instead."
	got := formatRemediationHTML(input)

	// Verify structure.
	assert.True(t, strings.HasPrefix(got, `<details class="remediation"><summary>Show Fix</summary>`))
	assert.True(t, strings.HasSuffix(got, "</details>"))
	assert.Contains(t, got, `<pre class="code-block language-yaml"><code>spec:
  hostNetwork: false</code></pre>`)
	assert.Contains(t, got, "Container shares the host network namespace")
	assert.Contains(t, got, "Use Services and Ingress")
}

func TestFormatRemediationHTML_CodeBlockNoLang(t *testing.T) {
	input := "Example:\n\n```\nsome code\n```"
	got := formatRemediationHTML(input)
	assert.Contains(t, got, `<pre class="code-block"><code>`)
}

func TestFormatRemediationBody_H3Header(t *testing.T) {
	got := formatRemediationBody("## Why This Matters")
	assert.Contains(t, got, `<h3 class="rem-h3">Why This Matters</h3>`)
	assert.NotContains(t, got, "<p>")
}

func TestFormatRemediationBody_H4Header(t *testing.T) {
	got := formatRemediationBody("### Steps to Fix")
	assert.Contains(t, got, `<h4 class="rem-h4">Steps to Fix</h4>`)
	assert.NotContains(t, got, "<p>")
}

func TestFormatRemediationBody_MultipleHeaders(t *testing.T) {
	input := "## Why This Matters\n\nRunning as root is dangerous.\n\n### How to Fix\n\nSet runAsNonRoot:\n\n```yaml\nrunAsNonRoot: true\n```\n\n## Learn More\n\nSee K8s docs."
	got := formatRemediationBody(input)

	assert.Contains(t, got, `<h3 class="rem-h3">Why This Matters</h3>`)
	assert.Contains(t, got, "<p>Running as root is dangerous.</p>")
	assert.Contains(t, got, `<h4 class="rem-h4">How to Fix</h4>`)
	assert.Contains(t, got, `<h3 class="rem-h3">Learn More</h3>`)
	assert.Contains(t, got, `<pre class="code-block language-yaml"><code>`)
}

func TestFormatRemediationBody_HeaderEscapesHTML(t *testing.T) {
	got := formatRemediationBody("## <script>alert('xss')</script>")
	assert.Contains(t, got, `<h3 class="rem-h3">&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;</h3>`)
	assert.NotContains(t, got, "<script>")
}

func TestFormatRemediationBody_HeaderNotInline(t *testing.T) {
	got := formatRemediationBody("Some text ## not a header")
	assert.Contains(t, got, "<p>Some text ## not a header</p>")
	assert.NotContains(t, got, `<h3 class="rem-h3">`)
}

func TestFormatRemediationBody_FullStructuredRemediation(t *testing.T) {
	input := `## Why This Matters

Running containers as root grants unnecessary privileges. If compromised, an attacker gains root-level access to the container filesystem and potentially the host.

### How to Fix

Set runAsNonRoot in your pod security context:

` + "```yaml\nspec:\n  securityContext:\n    runAsNonRoot: true\n    runAsUser: 1000\n```" + `

This ensures the container process runs as a non-root user.

## Learn More

Refer to the Kubernetes documentation on Pod Security Standards and CIS Benchmark 5.2.6.`

	got := formatRemediationBody(input)

	// Three section headers present.
	assert.Equal(t, 2, strings.Count(got, `<h3 class="rem-h3">`), "should have 2 h3 headers")
	assert.Equal(t, 1, strings.Count(got, `<h4 class="rem-h4">`), "should have 1 h4 header")

	// Section content present.
	assert.Contains(t, got, "Running containers as root")
	assert.Contains(t, got, "runAsNonRoot: true")
	assert.Contains(t, got, "CIS Benchmark 5.2.6")

	// Code block rendered.
	assert.Contains(t, got, `<pre class="code-block language-yaml"><code>`)
}
