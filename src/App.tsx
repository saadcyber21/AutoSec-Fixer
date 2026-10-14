import { useState } from 'react';
import { Shield, Code, FileText, Terminal, GitBranch, Zap, ChevronRight, Menu, X } from 'lucide-react';
import CodeBlock from './components/CodeBlock';
import {
  ingestCode,
  contextCode,
  agentCode,
  patchCode,
  mainCode,
  requirementsTxt,
} from './data/codeFiles';

type Section = 'overview' | 'architecture' | 'install' | 'usage' | 'ingest' | 'context' | 'agent' | 'patch' | 'main' | 'requirements';

const sections: { id: Section; label: string; icon: React.ReactNode }[] = [
  { id: 'overview', label: 'Overview', icon: <Shield size={16} /> },
  { id: 'architecture', label: 'Architecture', icon: <Zap size={16} /> },
  { id: 'install', label: 'Installation', icon: <Terminal size={16} /> },
  { id: 'usage', label: 'Usage', icon: <FileText size={16} /> },
  { id: 'ingest', label: 'ingest.py', icon: <Code size={16} /> },
  { id: 'context', label: 'context.py', icon: <Code size={16} /> },
  { id: 'agent', label: 'agent.py', icon: <Code size={16} /> },
  { id: 'patch', label: 'patch.py', icon: <Code size={16} /> },
  { id: 'main', label: 'main.py', icon: <Code size={16} /> },
  { id: 'requirements', label: 'requirements.txt', icon: <FileText size={16} /> },
];

export default function App() {
  const [activeSection, setActiveSection] = useState<Section>('overview');
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  return (
    <div className="min-h-screen bg-[#0d1117] text-gray-100">
      {/* Header */}
      <header className="sticky top-0 z-50 bg-[#161b22]/95 backdrop-blur-md border-b border-gray-700/50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-emerald-400 to-cyan-500 flex items-center justify-center">
                <Shield size={20} className="text-white" />
              </div>
              <div>
                <h1 className="text-lg font-bold text-white">AutoSec-Fixer</h1>
                <p className="text-xs text-gray-400 -mt-0.5">Autonomous AI Security Remediation</p>
              </div>
            </div>
            <div className="hidden md:flex items-center gap-4">
              <span className="text-xs px-2.5 py-1 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                v1.0.0
              </span>
              <span className="text-xs px-2.5 py-1 rounded-full bg-blue-500/10 text-blue-400 border border-blue-500/20">
                Python 3.11+
              </span>
              <span className="text-xs px-2.5 py-1 rounded-full bg-purple-500/10 text-purple-400 border border-purple-500/20">
                MIT License
              </span>
            </div>
            <button
              className="md:hidden p-2 text-gray-400 hover:text-white"
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            >
              {mobileMenuOpen ? <X size={20} /> : <Menu size={20} />}
            </button>
          </div>
        </div>
      </header>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex">
        {/* Sidebar */}
        <aside className={`${mobileMenuOpen ? 'fixed inset-0 z-40 bg-[#0d1117] pt-16' : 'hidden'} md:block md:sticky md:top-16 md:w-56 lg:w-64 md:h-[calc(100vh-4rem)] md:overflow-y-auto md:flex-shrink-0`}>
          <nav className="py-6 px-2 space-y-1">
            <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider px-3 mb-3">Documentation</p>
            {sections.map((section) => (
              <button
                key={section.id}
                onClick={() => { setActiveSection(section.id); setMobileMenuOpen(false); }}
                className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm transition-all ${
                  activeSection === section.id
                    ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                    : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800/50'
                }`}
              >
                {section.icon}
                <span>{section.label}</span>
                {activeSection === section.id && <ChevronRight size={14} className="ml-auto" />}
              </button>
            ))}
          </nav>
        </aside>

        {/* Main Content */}
        <main className="flex-1 min-w-0 py-8 px-0 md:px-8">
          {activeSection === 'overview' && <OverviewSection />}
          {activeSection === 'architecture' && <ArchitectureSection />}
          {activeSection === 'install' && <InstallSection />}
          {activeSection === 'usage' && <UsageSection />}
          {activeSection === 'ingest' && <CodeSection title="ingest.py" subtitle="Vulnerability Report Parser Module" code={ingestCode} language="python" />}
          {activeSection === 'context' && <CodeSection title="context.py" subtitle="Code Context Extraction Module" code={contextCode} language="python" />}
          {activeSection === 'agent' && <CodeSection title="agent.py" subtitle="LLM Orchestration Agent Module" code={agentCode} language="python" />}
          {activeSection === 'patch' && <CodeSection title="patch.py" subtitle="Patch Application & Diff Generation" code={patchCode} language="python" />}
          {activeSection === 'main' && <CodeSection title="main.py" subtitle="CLI Entry Point & Pipeline Orchestrator" code={mainCode} language="python" />}
          {activeSection === 'requirements' && <CodeSection title="requirements.txt" subtitle="Python Dependencies" code={requirementsTxt} language="ini" />}
        </main>
      </div>
    </div>
  );
}

function OverviewSection() {
  return (
    <div className="space-y-8">
      <div>
        <h2 className="text-3xl font-bold text-white mb-2">AutoSec-Fixer</h2>
        <p className="text-lg text-gray-400">
          Autonomous AI Security Remediation Agent — An XBOW-lite equivalent that takes vulnerability reports,
          analyzes affected codebases, generates secure patches, and outputs unified diffs.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <FeatureCard
          icon={<Shield className="text-emerald-400" size={24} />}
          title="Multi-Format Parsing"
          description="Supports SARIF, Semgrep, Bandit, and generic JSON vulnerability reports."
        />
        <FeatureCard
          icon={<Zap className="text-cyan-400" size={24} />}
          title="AI-Powered Remediation"
          description="LLM-driven secure code generation with validation and retry logic."
        />
        <FeatureCard
          icon={<GitBranch className="text-purple-400" size={24} />}
          title="Git Integration"
          description="Automatic patch application, diff generation, and commit creation."
        />
      </div>

      <div className="bg-gray-800/30 rounded-xl border border-gray-700/50 p-6">
        <h3 className="text-lg font-semibold text-white mb-4">Key Features</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {[
            'SARIF v2.1.0, Semgrep, Bandit format support',
            'Intelligent context windowing with token budget',
            'AST-based Python function boundary detection',
            'Multi-language support (15+ languages)',
            'OpenAI & Anthropic provider abstraction',
            'Exponential backoff retry with error feedback',
            'Robust JSON extraction from LLM outputs',
            'Syntax validation & dangerous pattern detection',
            'CWE-specific security guidance (8+ categories)',
            'Multi-strategy code replacement (exact → fuzzy)',
            'Unified diff output with vulnerability metadata',
            'Batch processing with reverse-order application',
            'Automatic backup creation before patching',
            'Git commit with auto-generated messages',
            'Dry-run mode for safe preview',
            'Comprehensive CLI with filtering options',
          ].map((feature, i) => (
            <div key={i} className="flex items-start gap-2">
              <span className="text-emerald-400 mt-0.5">✓</span>
              <span className="text-sm text-gray-300">{feature}</span>
            </div>
          ))}
        </div>
      </div>

      <div className="bg-gray-800/30 rounded-xl border border-gray-700/50 p-6">
        <h3 className="text-lg font-semibold text-white mb-4">Tech Stack</h3>
        <div className="flex flex-wrap gap-2">
          {['Python 3.11+', 'OpenAI SDK', 'Anthropic SDK', 'LangChain', 'argparse', 'AST Module', 'difflib', 'subprocess', 'pydantic', 'rich'].map((tech) => (
            <span key={tech} className="px-3 py-1.5 rounded-lg bg-gray-700/50 text-sm text-gray-300 border border-gray-600/30">
              {tech}
            </span>
          ))}
        </div>
      </div>

      <div className="bg-amber-500/5 border border-amber-500/20 rounded-xl p-5">
        <div className="flex items-start gap-3">
          <span className="text-amber-400 text-xl">⚠️</span>
          <div>
            <h4 className="font-semibold text-amber-300 mb-1">Security Disclaimer</h4>
            <p className="text-sm text-gray-400">
              This tool generates code patches using AI/LLMs. Always review generated patches before applying
              them to production code. The agent does NOT execute generated code — it only generates patches.
              Security remediation should always be verified by a qualified security professional.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

function ArchitectureSection() {
  return (
    <div className="space-y-8">
      <div>
        <h2 className="text-3xl font-bold text-white mb-2">Architecture</h2>
        <p className="text-gray-400">End-to-end pipeline from vulnerability report to secure code patch.</p>
      </div>

      <div className="bg-gray-800/30 rounded-xl border border-gray-700/50 p-6 overflow-x-auto">
        <h3 className="text-lg font-semibold text-white mb-4">Pipeline Diagram</h3>
        <pre className="text-xs sm:text-sm text-gray-300 font-mono leading-relaxed whitespace-pre">
{`┌─────────────────────────────────────────────────────────────────────────────┐
│                          AutoSec-Fixer Pipeline                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐                  │
│  │   INGEST     │───▶│   CONTEXT    │───▶│    AGENT     │                  │
│  │  (ingest.py) │    │ (context.py) │    │  (agent.py)  │                  │
│  │              │    │              │    │              │                  │
│  │ • SARIF      │    │ • File read  │    │ • LLM prompt │                  │
│  │ • Semgrep    │    │ • ±20 lines  │    │ • Code gen   │                  │
│  │ • Bandit     │    │ • AST parse  │    │ • Validate   │                  │
│  │ • Generic    │    │ • Token mgmt │    │ • Retry loop │                  │
│  └──────────────┘    └──────────────┘    └──────┬───────┘                  │
│                                                  │                          │
│                                                  ▼                          │
│                                          ┌──────────────┐                  │
│                                          │    PATCH     │                  │
│                                          │  (patch.py)  │                  │
│                                          │              │                  │
│                                          │ • Apply fix  │                  │
│                                          │ • Gen diff   │                  │
│                                          │ • Git commit │                  │
│                                          │ • .patch out │                  │
│                                          └──────┬───────┘                  │
│                                                  │                          │
│                                                  ▼                          │
│                                    ┌─────────────────────────┐             │
│                                    │       OUTPUT            │             │
│                                    │                         │             │
│                                    │ • Unified diffs (.diff) │             │
│                                    │ • Combined .patch file  │             │
│                                    │ • Git commit            │             │
│                                    │ • JSON summary report   │             │
│                                    └─────────────────────────┘             │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘`}
        </pre>
      </div>

      <div className="bg-gray-800/30 rounded-xl border border-gray-700/50 p-6">
        <h3 className="text-lg font-semibold text-white mb-4">Data Flow</h3>
        <div className="space-y-4">
          <FlowStep
            step={1}
            title="Ingest (ingest.py)"
            description="Parses vulnerability reports from SARIF, Semgrep, Bandit, or generic JSON formats. Normalizes findings into a common Vulnerability dataclass with file path, line numbers, CWE ID, severity, and metadata."
            color="emerald"
          />
          <FlowStep
            step={2}
            title="Context (context.py)"
            description="Reads the vulnerable source file and extracts ±20 lines of surrounding context. Uses AST analysis for Python to identify function boundaries. Enforces token budget limits to prevent context window overflow."
            color="cyan"
          />
          <FlowStep
            step={3}
            title="Agent (agent.py)"
            description="Core LLM orchestration loop. Constructs security-focused prompts with CWE-specific guidance. Sends to OpenAI/Anthropic, parses JSON response, validates syntax and dangerous patterns. Retries with error feedback on failure."
            color="purple"
          />
          <FlowStep
            step={4}
            title="Patch (patch.py)"
            description="Applies the generated patch using multi-strategy replacement (exact match → file search → fuzzy match). Creates backups, generates unified diffs, and optionally creates Git commits with auto-generated messages."
            color="amber"
          />
        </div>
      </div>

      <div className="bg-gray-800/30 rounded-xl border border-gray-700/50 p-6">
        <h3 className="text-lg font-semibold text-white mb-4">Module Dependencies</h3>
        <pre className="text-sm text-gray-300 font-mono">
{`main.py
  ├── ingest.py          (VulnerabilityIngestor, VulnerabilityReport)
  ├── context.py         (ContextExtractor, CodeContext)
  ├── agent.py           (SecurityRemediationAgent, OpenAIProvider, AnthropicProvider)
  │     └── context.py   (CodeContext)
  │     └── ingest.py    (Vulnerability)
  └── patch.py           (PatchApplier, PatchResult, PatchSet)
        ├── agent.py     (PatchProposal)
        └── ingest.py    (Vulnerability)`}
        </pre>
      </div>

      <div className="bg-gray-800/30 rounded-xl border border-gray-700/50 p-6">
        <h3 className="text-lg font-semibold text-white mb-4">Supported Vulnerability Formats</h3>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-700">
                <th className="text-left py-2 px-3 text-gray-400">Format</th>
                <th className="text-left py-2 px-3 text-gray-400">Detection</th>
                <th className="text-left py-2 px-3 text-gray-400">Fields Extracted</th>
              </tr>
            </thead>
            <tbody className="text-gray-300">
              <tr className="border-b border-gray-800">
                <td className="py-2 px-3 font-mono text-emerald-400">SARIF v2.1.0</td>
                <td className="py-2 px-3">$schema or runs key</td>
                <td className="py-2 px-3">file, lines, CWE, severity, rule</td>
              </tr>
              <tr className="border-b border-gray-800">
                <td className="py-2 px-3 font-mono text-cyan-400">Semgrep</td>
                <td className="py-2 px-3">results + errors keys</td>
                <td className="py-2 px-3">path, lines, CWE, severity, metadata</td>
              </tr>
              <tr className="border-b border-gray-800">
                <td className="py-2 px-3 font-mono text-purple-400">Bandit</td>
                <td className="py-2 px-3">generated_at + test_id</td>
                <td className="py-2 px-3">filename, lines, CWE, severity</td>
              </tr>
              <tr>
                <td className="py-2 px-3 font-mono text-amber-400">Generic JSON</td>
                <td className="py-2 px-3">vulnerabilities/findings key</td>
                <td className="py-2 px-3">file, line, severity, message</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

function InstallSection() {
  return (
    <div className="space-y-8">
      <div>
        <h2 className="text-3xl font-bold text-white mb-2">Installation</h2>
        <p className="text-gray-400">Get up and running with AutoSec-Fixer in minutes.</p>
      </div>

      <div className="bg-gray-800/30 rounded-xl border border-gray-700/50 p-6">
        <h3 className="text-lg font-semibold text-white mb-4">Prerequisites</h3>
        <ul className="space-y-2 text-gray-300">
          <li className="flex items-center gap-2"><span className="text-emerald-400">•</span> Python 3.11 or higher</li>
          <li className="flex items-center gap-2"><span className="text-emerald-400">•</span> An API key for OpenAI or Anthropic</li>
          <li className="flex items-center gap-2"><span className="text-emerald-400">•</span> Git (optional, for commit creation)</li>
        </ul>
      </div>

      <div className="space-y-4">
        <h3 className="text-lg font-semibold text-white">Setup Steps</h3>

        <CodeBlock
          language="bash"
          filename="Terminal"
          code={`# Clone the repository
git clone https://github.com/your-org/autosec-fixer.git
cd autosec-fixer

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .venv\\Scripts\\activate   # Windows

# Install dependencies
pip install -r requirements.txt`}
        />

        <CodeBlock
          language="bash"
          filename="Set API Key"
          code={`# For OpenAI
export OPENAI_API_KEY="sk-..."

# For Anthropic
export ANTHROPIC_API_KEY="sk-ant-..."`}
        />
      </div>

      <div className="bg-gray-800/30 rounded-xl border border-gray-700/50 p-6">
        <h3 className="text-lg font-semibold text-white mb-4">Project Structure</h3>
        <CodeBlock
          language="bash"
          code={`autosec-fixer/
├── main.py              # CLI entry point & pipeline orchestration
├── ingest.py            # Vulnerability report parser (SARIF/JSON)
├── context.py           # Code context extraction & AST analysis
├── agent.py             # LLM orchestration & prompt engineering
├── patch.py             # Patch application & diff generation
├── requirements.txt     # Python dependencies
├── README.md            # Documentation
├── tests/
│   ├── test_ingest.py   # Ingestion unit tests
│   ├── test_context.py  # Context extraction tests
│   ├── test_agent.py    # Agent orchestration tests
│   └── test_patch.py    # Patch application tests
└── examples/
    ├── semgrep.json     # Example Semgrep output
    ├── bandit.json      # Example Bandit output
    └── sample.sarif     # Example SARIF report`}
        />
      </div>
    </div>
  );
}

function UsageSection() {
  return (
    <div className="space-y-8">
      <div>
        <h2 className="text-3xl font-bold text-white mb-2">Usage</h2>
        <p className="text-gray-400">Command-line interface and examples for running the remediation pipeline.</p>
      </div>

      <div className="space-y-4">
        <h3 className="text-lg font-semibold text-white">Basic Usage</h3>
        <CodeBlock
          language="bash"
          filename="Terminal"
          code={`# Process a Semgrep report
python main.py --report semgrep_results.json --repo /path/to/codebase

# Process a Bandit report with Anthropic Claude
python main.py --report bandit_output.json --repo ./myproject --provider anthropic

# Dry run (generate patches without modifying files)
python main.py --report findings.sarif --repo ./app --dry-run`}
        />
      </div>

      <div className="space-y-4">
        <h3 className="text-lg font-semibold text-white">Advanced Options</h3>
        <CodeBlock
          language="bash"
          filename="Terminal"
          code={`# Filter by severity (only HIGH and above)
python main.py --report results.json --repo ./code --severity HIGH

# Limit to specific files
python main.py --report results.json --repo ./code --file-filter "src/auth/*.py"

# Process only first 10 vulnerabilities
python main.py --report results.json --repo ./code --max-vulns 10

# Create a Git commit after patching
python main.py --report results.json --repo ./code --git-commit

# Full verbose output with extended context
python main.py --report results.json --repo ./code -v --context-lines 30`}
        />
      </div>

      <div className="bg-gray-800/30 rounded-xl border border-gray-700/50 p-6">
        <h3 className="text-lg font-semibold text-white mb-4">CLI Reference</h3>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-700">
                <th className="text-left py-2 px-3 text-gray-400">Flag</th>
                <th className="text-left py-2 px-3 text-gray-400">Description</th>
                <th className="text-left py-2 px-3 text-gray-400">Default</th>
              </tr>
            </thead>
            <tbody className="text-gray-300">
              {[
                ['--report, -r', 'Path to vulnerability report', 'Required'],
                ['--repo, -p', 'Path to source code repository', 'Required'],
                ['--provider', 'LLM provider (openai/anthropic)', 'openai'],
                ['--model', 'Specific model identifier', 'gpt-4-turbo'],
                ['--api-key', 'API key (or use env vars)', '—'],
                ['--severity', 'Minimum severity threshold', 'All'],
                ['--max-vulns', 'Maximum vulns to process', 'All'],
                ['--file-filter', 'Glob pattern for files', 'All'],
                ['--dry-run', 'Preview without modifying', 'false'],
                ['--output-dir', 'Output directory', './autosecfix_output'],
                ['--no-backup', 'Skip backup creation', 'false'],
                ['--git-commit', 'Create Git commit', 'false'],
                ['--context-lines', 'Context lines ±N', '20'],
                ['--verbose, -v', 'Debug logging', 'false'],
                ['--quiet, -q', 'Suppress non-error output', 'false'],
              ].map(([flag, desc, def_], i) => (
                <tr key={i} className="border-b border-gray-800/50">
                  <td className="py-2 px-3 font-mono text-xs text-emerald-400">{flag}</td>
                  <td className="py-2 px-3">{desc}</td>
                  <td className="py-2 px-3 text-gray-500">{def_}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="bg-gray-800/30 rounded-xl border border-gray-700/50 p-6">
        <h3 className="text-lg font-semibold text-white mb-4">Example Output</h3>
        <CodeBlock
          language="bash"
          code={`$ python main.py --report semgrep.json --repo ./myapp --dry-run

2024-01-15 10:30:00 [INFO] autosec-fixer: ============================================================
2024-01-15 10:30:00 [INFO] autosec-fixer: AutoSec-Fixer - Autonomous Security Remediation
2024-01-15 10:30:00 [INFO] autosec-fixer: ============================================================
2024-01-15 10:30:00 [INFO] autosec-fixer: Report: semgrep.json
2024-01-15 10:30:00 [INFO] autosec-fixer: Repository: ./myapp
2024-01-15 10:30:00 [INFO] autosec-fixer: Provider: openai
2024-01-15 10:30:00 [INFO] autosec-fixer: Mode: DRY RUN

2024-01-15 10:30:01 [INFO] autosec-fixer: [Phase 1] Parsing vulnerability report...
2024-01-15 10:30:01 [INFO] autosec-fixer:   Tool: semgrep
2024-01-15 10:30:01 [INFO] autosec-fixer:   Total: 5
2024-01-15 10:30:01 [INFO] autosec-fixer:   HIGH: 2
2024-01-15 10:30:01 [INFO] autosec-fixer:   MEDIUM: 3

2024-01-15 10:30:02 [INFO] autosec-fixer: [Phase 3] Analyzing code and generating patches...
2024-01-15 10:30:02 [INFO] autosec-fixer:   [1/5] src/routes/user_profile.py:45
2024-01-15 10:30:05 [INFO] autosec-fixer:     Patch generated (confidence: 0.92)
2024-01-15 10:30:05 [INFO] autosec-fixer:   [2/5] src/db/queries.py:112
2024-01-15 10:30:08 [INFO] autosec-fixer:     Patch generated (confidence: 0.88)
...

Patch Set Summary:
  Total patches: 5
  Successful: 5
  Failed: 0
  Files modified: 3
  Lines changed: 24`}
        />
      </div>
    </div>
  );
}

function CodeSection({ title, subtitle, code, language }: { title: string; subtitle: string; code: string; language: string }) {
  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-3xl font-bold text-white mb-1">{title}</h2>
        <p className="text-gray-400">{subtitle}</p>
      </div>
      <CodeBlock code={code} language={language} filename={title} maxHeight="700px" />
    </div>
  );
}

function FeatureCard({ icon, title, description }: { icon: React.ReactNode; title: string; description: string }) {
  return (
    <div className="bg-gray-800/30 rounded-xl border border-gray-700/50 p-5 hover:border-gray-600/50 transition-colors">
      <div className="mb-3">{icon}</div>
      <h3 className="font-semibold text-white mb-1">{title}</h3>
      <p className="text-sm text-gray-400">{description}</p>
    </div>
  );
}

function FlowStep({ step, title, description, color }: { step: number; title: string; description: string; color: string }) {
  const colorClasses: Record<string, string> = {
    emerald: 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400',
    cyan: 'bg-cyan-500/10 border-cyan-500/30 text-cyan-400',
    purple: 'bg-purple-500/10 border-purple-500/30 text-purple-400',
    amber: 'bg-amber-500/10 border-amber-500/30 text-amber-400',
  };

  return (
    <div className="flex items-start gap-4">
      <div className={`w-8 h-8 rounded-lg flex items-center justify-center text-sm font-bold border ${colorClasses[color]}`}>
        {step}
      </div>
      <div>
        <h4 className="font-semibold text-white mb-1">{title}</h4>
        <p className="text-sm text-gray-400">{description}</p>
      </div>
    </div>
  );
}
