export const ingestCode = `"""
ingest.py - Vulnerability Report Parser Module
================================================

Parses incoming vulnerability data from static analysis tools.
Supports SARIF (Static Analysis Results Interchange Format) and
custom JSON formats containing file paths, line numbers, and
CWE/vulnerability details.

Author: AutoSec-Fixer Team
License: MIT
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger(__name__)


@dataclass
class Vulnerability:
    """Represents a single vulnerability finding from a static analyzer.

    Attributes:
        file_path: Relative path to the vulnerable file.
        line_start: Starting line number of the vulnerable code.
        line_end: Ending line number of the vulnerable code.
        cwe_id: CWE identifier (e.g., 'CWE-79' for XSS).
        severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO).
        message: Human-readable description of the vulnerability.
        rule_id: The analyzer rule/check identifier.
        tool: Name of the originating analysis tool.
        metadata: Additional tool-specific metadata.
    """

    file_path: str
    line_start: int
    line_end: int
    cwe_id: Optional[str] = None
    severity: str = "MEDIUM"
    message: str = ""
    rule_id: Optional[str] = None
    tool: str = "unknown"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate and normalize vulnerability data after initialization."""
        if self.line_start < 1:
            raise ValueError(f"line_start must be >= 1, got {self.line_start}")
        if self.line_end < self.line_start:
            self.line_end = self.line_start
        self.severity = self.severity.upper()
        if self.severity not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            logger.warning(f"Unknown severity '{self.severity}', defaulting to MEDIUM")
            self.severity = "MEDIUM"


@dataclass
class VulnerabilityReport:
    """Container for a parsed vulnerability report.

    Attributes:
        tool: Name of the analysis tool that generated the report.
        schema_version: Version of the report schema.
        vulnerabilities: List of parsed vulnerability findings.
        raw_data: The original parsed JSON/SARIF data.
    """

    tool: str
    schema_version: str
    vulnerabilities: List[Vulnerability]
    raw_data: Dict[str, Any] = field(default_factory=dict)

    @property
    def total_count(self) -> int:
        """Return total number of vulnerabilities."""
        return len(self.vulnerabilities)

    @property
    def by_severity(self) -> Dict[str, List[Vulnerability]]:
        """Group vulnerabilities by severity level."""
        grouped: Dict[str, List[Vulnerability]] = {}
        for vuln in self.vulnerabilities:
            grouped.setdefault(vuln.severity, []).append(vuln)
        return grouped

    def filter_by_severity(self, min_severity: str) -> List[Vulnerability]:
        """Filter vulnerabilities by minimum severity threshold."""
        severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        threshold = severity_order.get(min_severity.upper(), 0)
        return [
            v for v in self.vulnerabilities
            if severity_order.get(v.severity, 0) >= threshold
        ]


class IngestionError(Exception):
    """Raised when vulnerability report parsing fails."""
    pass


class VulnerabilityIngestor:
    """Parses vulnerability reports from static analysis tools.

    Supports SARIF v2.1.0 format and simplified JSON formats from
    tools like Semgrep, Bandit, and custom analyzers.
    """

    SUPPORTED_FORMATS = {"sarif", "json"}

    def __init__(self) -> None:
        self._parsers = {
            "sarif": self._parse_sarif,
            "semgrep": self._parse_semgrep,
            "bandit": self._parse_bandit,
            "generic": self._parse_generic_json,
        }

    def parse_file(self, file_path: Union[str, Path]) -> VulnerabilityReport:
        """Parse a vulnerability report from a file."""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Report file not found: {path}")
        if not path.is_file():
            raise IngestionError(f"Path is not a file: {path}")
        try:
            with open(path, "r", encoding="utf-8") as f:
                raw_data = json.load(f)
        except json.JSONDecodeError as e:
            raise IngestionError(f"Invalid JSON in report file: {e}")
        except IOError as e:
            raise IngestionError(f"Failed to read report file: {e}")

        format_type = self._detect_format(raw_data)
        logger.info(f"Detected report format: {format_type}")
        parser = self._parsers.get(format_type, self._parse_generic_json)
        return parser(raw_data)

    def parse_string(self, data: str) -> VulnerabilityReport:
        """Parse a vulnerability report from a JSON string."""
        try:
            raw_data = json.loads(data)
        except json.JSONDecodeError as e:
            raise IngestionError(f"Invalid JSON data: {e}")
        format_type = self._detect_format(raw_data)
        parser = self._parsers.get(format_type, self._parse_generic_json)
        return parser(raw_data)

    def _detect_format(self, data: Dict[str, Any]) -> str:
        """Detect the format of the vulnerability report."""
        if "$schema" in data and "sarif" in data.get("$schema", "").lower():
            return "sarif"
        if "runs" in data and isinstance(data["runs"], list):
            return "sarif"
        if "results" in data and "errors" in data:
            return "semgrep"
        if "generated_at" in data and "results" in data:
            if any("test_id" in r for r in data.get("results", [])[:5]):
                return "bandit"
        return "generic"

    def _parse_sarif(self, data: Dict[str, Any]) -> VulnerabilityReport:
        """Parse a SARIF v2.1.0 format report."""
        vulnerabilities: List[Vulnerability] = []
        tool_name = "unknown"
        runs = data.get("runs", [])
        if not runs:
            raise IngestionError("SARIF report contains no runs")

        for run in runs:
            tool_info = run.get("tool", {})
            driver = tool_info.get("driver", {})
            tool_name = driver.get("name", tool_name)

            rules = {}
            for rule in driver.get("rules", []):
                rule_id = rule.get("id", "")
                properties = rule.get("properties", {})
                cwe_ids = properties.get("tags", [])
                cwe = None
                for tag in cwe_ids:
                    if "CWE-" in str(tag):
                        cwe = str(tag)
                        break
                rules[rule_id] = {
                    "cwe": cwe,
                    "description": rule.get("shortDescription", {}).get("text", ""),
                }

            for result in run.get("results", []):
                rule_id = result.get("ruleId", "")
                message = result.get("message", {}).get("text", "")
                level = result.get("level", "warning").upper()
                severity_map = {"ERROR": "HIGH", "WARNING": "MEDIUM", "NOTE": "LOW", "NONE": "INFO"}
                severity = severity_map.get(level, "MEDIUM")

                locations = result.get("locations", [])
                for location in locations:
                    phys = location.get("physicalLocation", {})
                    artifact = phys.get("artifactLocation", {})
                    file_path = artifact.get("uri", "")
                    region = phys.get("region", {})
                    line_start = region.get("startLine", 1)
                    line_end = region.get("endLine", line_start)
                    rule_info = rules.get(rule_id, {})
                    cwe_id = rule_info.get("cwe")

                    vuln = Vulnerability(
                        file_path=file_path, line_start=line_start, line_end=line_end,
                        cwe_id=cwe_id, severity=severity, message=message,
                        rule_id=rule_id, tool=tool_name,
                    )
                    vulnerabilities.append(vuln)

        return VulnerabilityReport(tool=tool_name, schema_version="2.1.0",
                                   vulnerabilities=vulnerabilities, raw_data=data)

    def _parse_semgrep(self, data: Dict[str, Any]) -> VulnerabilityReport:
        """Parse a Semgrep JSON output format."""
        vulnerabilities: List[Vulnerability] = []
        for result in data.get("results", []):
            check_id = result.get("check_id", "")
            path = result.get("path", "")
            start = result.get("start", {})
            end = result.get("end", {})
            extra = result.get("extra", {})
            message = extra.get("message", "")
            severity = extra.get("severity", "WARNING").upper()
            severity_map = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
            mapped_severity = severity_map.get(severity, "MEDIUM")
            metadata = extra.get("metadata", {})
            cwe_list = metadata.get("cwe", [])
            cwe_id = cwe_list[0] if cwe_list else None

            vuln = Vulnerability(
                file_path=path, line_start=start.get("line", 1),
                line_end=end.get("line", start.get("line", 1)),
                cwe_id=cwe_id, severity=mapped_severity, message=message,
                rule_id=check_id, tool="semgrep", metadata=metadata,
            )
            vulnerabilities.append(vuln)

        return VulnerabilityReport(tool="semgrep", schema_version="1.0",
                                   vulnerabilities=vulnerabilities, raw_data=data)

    def _parse_bandit(self, data: Dict[str, Any]) -> VulnerabilityReport:
        """Parse a Bandit JSON output format."""
        vulnerabilities: List[Vulnerability] = []
        for result in data.get("results", []):
            file_path = result.get("filename", "")
            line_number = result.get("line_number", 1)
            line_range = result.get("line_range", [line_number, line_number])
            test_id = result.get("test_id", "")
            test_name = result.get("test_name", "")
            issue_text = result.get("issue_text", "")
            severity = result.get("issue_severity", "MEDIUM").upper()
            cwe_id = result.get("issue_cwe", {}).get("id")
            if cwe_id:
                cwe_id = f"CWE-{cwe_id}"
            vuln = Vulnerability(
                file_path=file_path, line_start=line_range[0] if line_range else line_number,
                line_end=line_range[-1] if line_range else line_number,
                cwe_id=cwe_id, severity=severity, message=issue_text,
                rule_id=f"{test_id}:{test_name}", tool="bandit",
            )
            vulnerabilities.append(vuln)
        return VulnerabilityReport(tool="bandit",
                                   schema_version=data.get("metrics", {}).get("_version", "1.0"),
                                   vulnerabilities=vulnerabilities, raw_data=data)

    def _parse_generic_json(self, data: Dict[str, Any]) -> VulnerabilityReport:
        """Parse a generic JSON vulnerability report."""
        vulnerabilities: List[Vulnerability] = []
        findings = (data.get("vulnerabilities") or data.get("findings")
                    or data.get("results") or data.get("issues"))
        if not findings or not isinstance(findings, list):
            raise IngestionError(
                "Could not find vulnerability data in generic JSON format. "
                "Expected keys: 'vulnerabilities', 'findings', 'results', or 'issues'."
            )
        for item in findings:
            if not isinstance(item, dict):
                continue
            file_path = (item.get("file") or item.get("file_path")
                         or item.get("path") or item.get("filename") or "")
            line_start = item.get("line") or item.get("line_start") or item.get("start_line") or 1
            line_end = item.get("end_line") or item.get("line_end") or line_start
            vuln = Vulnerability(
                file_path=str(file_path), line_start=int(line_start), line_end=int(line_end),
                cwe_id=item.get("cwe") or item.get("cwe_id"),
                severity=item.get("severity", "MEDIUM"),
                message=item.get("message") or item.get("description", ""),
                rule_id=item.get("rule_id") or item.get("rule") or item.get("check_id"),
                tool="generic", metadata=item,
            )
            vulnerabilities.append(vuln)
        return VulnerabilityReport(tool="generic", schema_version="1.0",
                                   vulnerabilities=vulnerabilities, raw_data=data)
`;

export const contextCode = `"""
context.py - Code Context Extraction Module
=============================================

Reads vulnerable files and retrieves surrounding code blocks to provide
the LLM with sufficient context for generating secure patches.

Author: AutoSec-Fixer Team
License: MIT
"""

from __future__ import annotations

import ast
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

MAX_CONTEXT_CHARS = 12000  # ~3000 tokens
DEFAULT_CONTEXT_LINES = 20


@dataclass
class CodeContext:
    """Represents extracted code context around a vulnerability."""
    file_path: str
    full_content: str
    vulnerable_block: str
    surrounding_context: str
    line_start: int
    line_end: int
    context_start: int
    context_end: int
    language: str = "python"
    imports: List[str] = field(default_factory=list)
    function_context: Optional[str] = None
    total_lines: int = 0

    @property
    def context_with_line_numbers(self) -> str:
        """Return context with line numbers for LLM reference."""
        lines = self.surrounding_context.split("\\n")
        numbered = []
        for i, line in enumerate(lines, start=self.context_start):
            marker = ">>>" if self.line_start <= i <= self.line_end else "   "
            numbered.append(f"{marker} {i:4d} | {line}")
        return "\\n".join(numbered)

    @property
    def token_estimate(self) -> int:
        """Estimate token count for context window management."""
        return len(self.surrounding_context) // 4


@dataclass
class FileAnalysis:
    """Analysis results for a source file."""
    file_path: str
    language: str
    total_lines: int
    functions: List[Tuple[str, int, int]] = field(default_factory=list)
    classes: List[Tuple[str, int, int]] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)


class ContextExtractionError(Exception):
    """Raised when context extraction fails."""
    pass


class ContextExtractor:
    """Extracts code context around vulnerabilities for LLM consumption."""

    LANGUAGE_EXTENSIONS: Dict[str, str] = {
        ".py": "python", ".js": "javascript", ".ts": "typescript",
        ".tsx": "typescript", ".jsx": "javascript", ".java": "java",
        ".go": "go", ".rs": "rust", ".rb": "ruby", ".php": "php",
        ".c": "c", ".cpp": "cpp", ".h": "c", ".hpp": "cpp",
        ".cs": "csharp", ".swift": "swift", ".kt": "kotlin",
    }

    def __init__(self, context_lines: int = DEFAULT_CONTEXT_LINES,
                 max_context_chars: int = MAX_CONTEXT_CHARS) -> None:
        self.context_lines = context_lines
        self.max_context_chars = max_context_chars

    def extract(self, file_path: str, line_start: int, line_end: int,
                repo_root: Optional[str] = None) -> CodeContext:
        """Extract code context around a vulnerability location."""
        path = self._resolve_path(file_path, repo_root)
        if not path.exists():
            raise FileNotFoundError(f"Source file not found: {path}")

        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            try:
                content = path.read_text(encoding="latin-1")
            except Exception as e:
                raise ContextExtractionError(f"Cannot read file {path}: {e}")
        except IOError as e:
            raise ContextExtractionError(f"Cannot read file {path}: {e}")

        lines = content.split("\\n")
        total_lines = len(lines)
        if line_start < 1 or line_start > total_lines:
            raise ContextExtractionError(
                f"Invalid line_start {line_start} for file with {total_lines} lines"
            )

        language = self._detect_language(path)
        context_start = max(1, line_start - self.context_lines)
        context_end = min(total_lines, line_end + self.context_lines)

        vulnerable_block = "\\n".join(lines[line_start - 1:line_end])
        surrounding_context = "\\n".join(lines[context_start - 1:context_end])

        if len(surrounding_context) > self.max_context_chars:
            surrounding_context = self._trim_context(lines, line_start, line_end, self.max_context_chars)

        imports = self._extract_imports(content, language)
        function_context = self._find_enclosing_function(content, line_start, language)

        return CodeContext(
            file_path=str(path), full_content=content,
            vulnerable_block=vulnerable_block, surrounding_context=surrounding_context,
            line_start=line_start, line_end=line_end,
            context_start=context_start, context_end=context_end,
            language=language, imports=imports,
            function_context=function_context, total_lines=total_lines,
        )

    def _resolve_path(self, file_path: str, repo_root: Optional[str] = None) -> Path:
        path = Path(file_path)
        if path.is_absolute():
            return path
        if repo_root:
            resolved = Path(repo_root) / path
            if resolved.exists():
                return resolved
        return path

    def _detect_language(self, path: Path) -> str:
        return self.LANGUAGE_EXTENSIONS.get(path.suffix.lower(), "unknown")

    def _trim_context(self, lines: List[str], line_start: int,
                      line_end: int, max_chars: int) -> str:
        vuln_lines = lines[line_start - 1:line_end]
        vuln_text = "\\n".join(vuln_lines)
        if len(vuln_text) >= max_chars:
            return vuln_text[:max_chars]
        remaining = max_chars - len(vuln_text)
        half = remaining // 2
        above, above_chars = [], 0
        for i in range(line_start - 2, -1, -1):
            ll = len(lines[i]) + 1
            if above_chars + ll > half:
                break
            above.insert(0, lines[i])
            above_chars += ll
        below, below_chars = [], 0
        for i in range(line_end, len(lines)):
            ll = len(lines[i]) + 1
            if below_chars + ll > half:
                break
            below.append(lines[i])
            below_chars += ll
        return "\\n".join(above + vuln_lines + below)

    def _extract_imports(self, content: str, language: str) -> List[str]:
        imports: List[str] = []
        if language == "python":
            for line in content.split("\\n"):
                stripped = line.strip()
                if stripped.startswith(("import ", "from ")):
                    imports.append(stripped)
        elif language in ("javascript", "typescript"):
            for line in content.split("\\n"):
                if line.strip().startswith("import "):
                    imports.append(line.strip())
        elif language == "java":
            for line in content.split("\\n"):
                if line.strip().startswith("import "):
                    imports.append(line.strip())
        return imports

    def _find_enclosing_function(self, content: str, target_line: int,
                                  language: str) -> Optional[str]:
        if language != "python":
            return self._generic_enclosing_function(content, target_line, language)
        lines = content.split("\\n")
        current_func: Optional[str] = None
        current_indent = -1
        for i, line in enumerate(lines, start=1):
            if i > target_line:
                break
            stripped = line.lstrip()
            indent = len(line) - len(stripped)
            if stripped.startswith("def ") or stripped.startswith("async def "):
                match = re.match(r"(?:async\\s+)?def\\s+(\\w+)", stripped)
                if match:
                    current_func = match.group(1)
                    current_indent = indent
            if current_func and indent <= current_indent and stripped:
                if not stripped.startswith(("def ", "async def ", "@", "#")):
                    if indent < current_indent:
                        current_func = None
        return current_func

    def _generic_enclosing_function(self, content: str, target_line: int,
                                     language: str) -> Optional[str]:
        lines = content.split("\\n")
        func_pattern = re.compile(r"(?:function|def|func|fn|pub\\s+fn)\\s+(\\w+)")
        current_func: Optional[str] = None
        brace_depth = 0
        for i, line in enumerate(lines, start=1):
            match = func_pattern.search(line)
            if match and brace_depth == 0:
                current_func = match.group(1)
            brace_depth += line.count("{") - line.count("}")
            if i == target_line:
                return current_func
            if brace_depth <= 0 and current_func:
                current_func = None
                brace_depth = 0
        return current_func
`;

export const agentCode = `"""
agent.py - LLM Orchestration Agent Module
==========================================

Core agent loop that orchestrates vulnerability analysis and secure
code patch generation using LLMs.

Author: AutoSec-Fixer Team
License: MIT
"""

from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Protocol, Tuple

from context import CodeContext
from ingest import Vulnerability

logger = logging.getLogger(__name__)


class AgentState(Enum):
    INITIALIZED = "initialized"
    ANALYZING = "analyzing"
    GENERATING = "generating"
    VALIDATING = "validating"
    COMPLETE = "complete"
    FAILED = "failed"
    RETRYING = "retrying"


class LLMProvider(Protocol):
    """Protocol for LLM provider implementations."""
    def generate(self, prompt: str, system: str, **kwargs: Any) -> str: ...
    def generate_with_retries(self, prompt: str, system: str,
                               max_retries: int = 3, **kwargs: Any) -> str: ...


class OpenAIProvider:
    """OpenAI API provider implementation."""
    def __init__(self, api_key: str, model: str = "gpt-4-turbo-preview") -> None:
        try:
            from openai import OpenAI
            self.client = OpenAI(api_key=api_key)
        except ImportError:
            raise ImportError("openai package required: pip install openai")
        self.model = model

    def generate(self, prompt: str, system: str, **kwargs: Any) -> str:
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            temperature=kwargs.get("temperature", 0.1),
            max_tokens=kwargs.get("max_tokens", 4096),
        )
        return response.choices[0].message.content or ""

    def generate_with_retries(self, prompt: str, system: str,
                               max_retries: int = 3, **kwargs: Any) -> str:
        last_error: Optional[Exception] = None
        for attempt in range(max_retries):
            try:
                return self.generate(prompt, system, **kwargs)
            except Exception as e:
                last_error = e
                time.sleep(2 ** attempt)
        raise RuntimeError(f"LLM failed after {max_retries} attempts: {last_error}")


class AnthropicProvider:
    """Anthropic Claude API provider implementation."""
    def __init__(self, api_key: str, model: str = "claude-3-opus-20240229") -> None:
        try:
            import anthropic
            self.client = anthropic.Anthropic(api_key=api_key)
        except ImportError:
            raise ImportError("anthropic package required: pip install anthropic")
        self.model = model

    def generate(self, prompt: str, system: str, **kwargs: Any) -> str:
        response = self.client.messages.create(
            model=self.model, system=system,
            messages=[{"role": "user", "content": prompt}],
            temperature=kwargs.get("temperature", 0.1),
            max_tokens=kwargs.get("max_tokens", 4096),
        )
        return response.content[0].text

    def generate_with_retries(self, prompt: str, system: str,
                               max_retries: int = 3, **kwargs: Any) -> str:
        last_error: Optional[Exception] = None
        for attempt in range(max_retries):
            try:
                return self.generate(prompt, system, **kwargs)
            except Exception as e:
                last_error = e
                time.sleep(2 ** attempt)
        raise RuntimeError(f"LLM failed after {max_retries} attempts: {last_error}")


@dataclass
class PatchProposal:
    """A proposed code patch from the LLM agent."""
    original_code: str
    patched_code: str
    explanation: str
    confidence: float = 0.0
    cwe_addressed: List[str] = field(default_factory=list)
    validation_notes: str = ""


@dataclass
class AgentResult:
    """Result from the agent's remediation attempt."""
    vulnerability: Vulnerability
    patch: Optional[PatchProposal] = None
    state: AgentState = AgentState.INITIALIZED
    attempts: int = 0
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class SecurityRemediationAgent:
    """Autonomous AI agent for security vulnerability remediation."""

    SYSTEM_PROMPT = """You are an elite application security engineer and secure coding expert.
Your task is to analyze vulnerable code and generate a secure replacement that:
1. ELIMINATES the vulnerability completely
2. PRESERVES the original functionality and behavior
3. FOLLOWS security best practices for the specific CWE category
4. MAINTAINS code style consistency with the surrounding codebase
5. INCLUDES security-relevant comments explaining the fix

You MUST respond in the following JSON format:
{
    "patched_code": "<the complete replacement code block>",
    "explanation": "<detailed explanation of the vulnerability and fix>",
    "confidence": <float 0.0-1.0>,
    "cwe_addressed": ["<CWE IDs addressed>"],
    "validation_notes": "<any concerns or testing recommendations>"
}

CRITICAL RULES:
- Output ONLY valid JSON, no markdown formatting
- The patched_code must be a drop-in replacement
- Do NOT change function signatures unless absolutely necessary
- Do NOT remove error handling or add unhandled code paths"""

    def __init__(self, provider: LLMProvider, max_retries: int = 3,
                 temperature: float = 0.1, enable_validation: bool = True) -> None:
        self.provider = provider
        self.max_retries = max_retries
        self.temperature = temperature
        self.enable_validation = enable_validation

    def remediate(self, vulnerability: Vulnerability, context: CodeContext) -> AgentResult:
        """Run the full remediation pipeline for a vulnerability."""
        result = AgentResult(vulnerability=vulnerability)
        try:
            result.state = AgentState.ANALYZING
            result.state = AgentState.GENERATING
            prompt = self._build_prompt(vulnerability, context)

            for attempt in range(1, self.max_retries + 1):
                result.attempts = attempt
                try:
                    response = self.provider.generate_with_retries(
                        prompt=prompt, system=self.SYSTEM_PROMPT,
                        temperature=self.temperature, max_retries=2,
                    )
                    patch = self._parse_response(response, context.vulnerable_block)
                    if patch:
                        if self.enable_validation:
                            result.state = AgentState.VALIDATING
                            if not self._validate_patch(patch, context):
                                if attempt < self.max_retries:
                                    prompt = self._build_retry_prompt(
                                        vulnerability, context, patch, "validation_failed")
                                    continue
                        result.patch = patch
                        result.state = AgentState.COMPLETE
                        return result
                except json.JSONDecodeError:
                    if attempt < self.max_retries:
                        prompt = self._build_retry_prompt(
                            vulnerability, context, None, "json_parse_error")
                        continue

            result.state = AgentState.FAILED
            result.error = "Failed to generate valid patch after all retries"
            return result
        except Exception as e:
            result.state = AgentState.FAILED
            result.error = str(e)
            return result

    def _build_prompt(self, vulnerability: Vulnerability, context: CodeContext) -> str:
        cwe_info = self._get_cwe_guidance(vulnerability.cwe_id)
        parts = [
            "## VULNERABILITY REPORT",
            f"- File: {vulnerability.file_path}",
            f"- Lines: {vulnerability.line_start}-{vulnerability.line_end}",
            f"- CWE: {vulnerability.cwe_id or 'Unknown'}",
            f"- Severity: {vulnerability.severity}",
            f"- Rule: {vulnerability.rule_id or 'N/A'}",
            f"- Description: {vulnerability.message}",
            "", "## CODE CONTEXT", f"Language: {context.language}",
        ]
        if context.function_context:
            parts.append(f"Enclosing function: {context.function_context}")
        if context.imports:
            parts.append(f"\\nImports: {', '.join(context.imports[:10])}")
        parts.extend([
            "", "## VULNERABLE CODE (with line numbers)",
            context.context_with_line_numbers,
            "", "## EXACT VULNERABLE BLOCK TO REPLACE",
            context.vulnerable_block, "",
        ])
        if cwe_info:
            parts.extend(["## SECURITY GUIDANCE", cwe_info, ""])
        parts.extend([
            "## INSTRUCTIONS",
            "Generate a secure replacement for the vulnerable code block.",
            "Respond with ONLY valid JSON in the specified format.",
        ])
        return "\\n".join(parts)

    def _build_retry_prompt(self, vulnerability: Vulnerability, context: CodeContext,
                             previous_patch: Optional[PatchProposal], error_type: str) -> str:
        base = self._build_prompt(vulnerability, context)
        if error_type == "json_parse_error":
            return base + "\\n\\nPREVIOUS ATTEMPT FAILED: Output was not valid JSON. Output ONLY valid JSON."
        elif error_type == "validation_failed" and previous_patch:
            return base + f"\\n\\nPREVIOUS FAILED VALIDATION: {previous_patch.validation_notes}"
        return base

    def _parse_response(self, response: str, original_code: str) -> Optional[PatchProposal]:
        try:
            data = json.loads(response)
            return self._create_patch(data, original_code)
        except json.JSONDecodeError:
            pass
        json_match = re.search(r"\`\`\`(?:json)?\\s*\\n?(\\{.*?\\})\\s*\\n?\`\`\`", response, re.DOTALL)
        if json_match:
            try:
                return self._create_patch(json.loads(json_match.group(1)), original_code)
            except json.JSONDecodeError:
                pass
        brace_match = re.search(r"\\{[^{}]*(?:\\{[^{}]*\\}[^{}]*)*\\}", response, re.DOTALL)
        if brace_match:
            try:
                return self._create_patch(json.loads(brace_match.group(0)), original_code)
            except json.JSONDecodeError:
                pass
        return None

    def _create_patch(self, data: Dict[str, Any], original_code: str) -> PatchProposal:
        patched_code = data.get("patched_code", "")
        if not patched_code:
            raise ValueError("Missing 'patched_code' in LLM response")
        confidence = max(0.0, min(1.0, float(data.get("confidence", 0.5))))
        cwe_addressed = data.get("cwe_addressed", [])
        if isinstance(cwe_addressed, str):
            cwe_addressed = [cwe_addressed]
        return PatchProposal(
            original_code=original_code, patched_code=patched_code,
            explanation=data.get("explanation", "No explanation provided"),
            confidence=confidence, cwe_addressed=cwe_addressed,
            validation_notes=data.get("validation_notes", ""),
        )

    def _validate_patch(self, patch: PatchProposal, context: CodeContext) -> bool:
        if not patch.patched_code.strip():
            return False
        if patch.patched_code.strip() == patch.original_code.strip():
            return False
        if context.language == "python":
            try:
                import ast
                ast.parse(patch.patched_code)
            except SyntaxError as e:
                patch.validation_notes = f"Syntax error: {e}"
                return False
        dangerous = [r"exec\\s*\\(", r"eval\\s*\\(", r"__import__\\s*\\(",
                     r"os\\.system\\s*\\(", r"subprocess\\.call\\s*\\(.*shell\\s*=\\s*True"]
        for pattern in dangerous:
            if re.search(pattern, patch.patched_code):
                patch.validation_notes = f"Dangerous pattern: {pattern}"
                return False
        if patch.confidence < 0.3:
            return False
        return True

    def _get_cwe_guidance(self, cwe_id: Optional[str]) -> str:
        guidance = {
            "CWE-79": "XSS: Use context-appropriate output encoding. Use html.escape() for HTML.",
            "CWE-89": "SQLi: Use parameterized queries. NEVER concatenate user input into SQL.",
            "CWE-22": "Path Traversal: Validate paths with os.path.realpath(). Ensure within allowed dir.",
            "CWE-78": "Command Injection: Avoid shell=True. Use subprocess.run() with list args.",
            "CWE-502": "Deserialization: Never pickle.loads() untrusted data. Use JSON.",
            "CWE-327": "Crypto: Use AES-256-GCM or ChaCha20. Never MD5/SHA1/DES for security.",
            "CWE-798": "Hardcoded Creds: Use env vars or secret managers. Remove all hardcoded secrets.",
            "CWE-611": "XXE: Use defusedxml. Set resolve_entities=False, forbid_dtd=True.",
        }
        if not cwe_id:
            return ""
        cwe_base = cwe_id.split(":")[0].strip()
        return guidance.get(cwe_base, f"Apply secure coding practices for {cwe_id}.")
`;

export const patchCode = `"""
patch.py - Patch Application and Diff Generation Module
========================================================

Applies LLM-generated code patches to source files, generates unified
diffs, and optionally creates Git commits or .patch files.

Author: AutoSec-Fixer Team
License: MIT
"""

from __future__ import annotations

import difflib
import logging
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from agent import PatchProposal
from ingest import Vulnerability

logger = logging.getLogger(__name__)


@dataclass
class PatchResult:
    """Result of applying a patch to a file."""
    file_path: str
    success: bool
    diff: str = ""
    backup_path: Optional[str] = None
    lines_changed: int = 0
    error: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass
class PatchSet:
    """Collection of patches to apply as a batch."""
    patches: List[PatchResult] = field(default_factory=list)
    total_files: int = 0
    total_changes: int = 0

    @property
    def all_successful(self) -> bool:
        return all(p.success for p in self.patches)

    @property
    def summary(self) -> str:
        successful = sum(1 for p in self.patches if p.success)
        failed = len(self.patches) - successful
        return (f"Patch Set Summary:\\n"
                f"  Total patches: {len(self.patches)}\\n"
                f"  Successful: {successful}\\n"
                f"  Failed: {failed}\\n"
                f"  Files modified: {self.total_files}\\n"
                f"  Lines changed: {self.total_changes}")


class PatchError(Exception):
    """Raised when patch application fails."""
    pass


class PatchApplier:
    """Applies code patches to source files and generates diffs."""

    def __init__(self, repo_root: Optional[str] = None,
                 create_backups: bool = True,
                 backup_suffix: str = ".autosecfix.bak") -> None:
        self.repo_root = Path(repo_root) if repo_root else None
        self.create_backups = create_backups
        self.backup_suffix = backup_suffix

    def apply_patch(self, vulnerability: Vulnerability, proposal: PatchProposal,
                    dry_run: bool = False) -> PatchResult:
        """Apply a single patch to the vulnerable file."""
        file_path = self._resolve_file_path(vulnerability.file_path)
        try:
            if not file_path.exists():
                return PatchResult(file_path=str(file_path), success=False,
                                   error=f"File not found: {file_path}")
            original_content = file_path.read_text(encoding="utf-8")
            original_lines = original_content.split("\\n")
            patched_content = self._apply_replacement(
                original_content, proposal.original_code, proposal.patched_code,
                vulnerability.line_start, vulnerability.line_end)
            if patched_content is None:
                return PatchResult(file_path=str(file_path), success=False,
                                   error="Failed to locate vulnerable code block")
            patched_lines = patched_content.split("\\n")
            diff = self._generate_diff(original_lines, patched_lines,
                                       str(file_path), vulnerability)
            lines_changed = len(patched_lines) - len(original_lines)
            if dry_run:
                return PatchResult(file_path=str(file_path), success=True,
                                   diff=diff, lines_changed=lines_changed)
            backup_path: Optional[str] = None
            if self.create_backups:
                backup_path = self._create_backup(file_path)
            file_path.write_text(patched_content, encoding="utf-8")
            return PatchResult(file_path=str(file_path), success=True,
                               diff=diff, backup_path=backup_path,
                               lines_changed=lines_changed)
        except Exception as e:
            return PatchResult(file_path=str(file_path), success=False, error=str(e))

    def apply_batch(self, patches: List[Tuple[Vulnerability, PatchProposal]],
                    dry_run: bool = False) -> PatchSet:
        """Apply multiple patches as a batch."""
        by_file: Dict[str, List[Tuple[Vulnerability, PatchProposal]]] = {}
        for vuln, proposal in patches:
            by_file.setdefault(vuln.file_path, []).append((vuln, proposal))
        results: List[PatchResult] = []
        for file_path, file_patches in by_file.items():
            file_patches.sort(key=lambda x: x[0].line_start, reverse=True)
            for vuln, proposal in file_patches:
                results.append(self.apply_patch(vuln, proposal, dry_run=dry_run))
        return PatchSet(
            patches=results, total_files=len(by_file),
            total_changes=sum(abs(r.lines_changed) for r in results if r.success))

    def generate_patch_file(self, patch_set: PatchSet,
                            output_path: Optional[str] = None) -> str:
        """Generate a .patch file from a patch set."""
        combined = "\\n".join(r.diff for r in patch_set.patches if r.success and r.diff)
        if not output_path:
            output_path = f"autosecfix_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.patch"
        Path(output_path).write_text(combined, encoding="utf-8")
        return output_path

    def create_git_commit(self, patch_set: PatchSet,
                          message: Optional[str] = None) -> bool:
        """Create a Git commit with the applied patches."""
        if not self.repo_root:
            return False
        try:
            result = subprocess.run(["git", "status"], cwd=str(self.repo_root),
                                     capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                return False
            for pr in patch_set.patches:
                if pr.success:
                    rel = os.path.relpath(pr.file_path, str(self.repo_root))
                    subprocess.run(["git", "add", rel], cwd=str(self.repo_root),
                                    capture_output=True, timeout=10)
            if not message:
                successful = [p for p in patch_set.patches if p.success]
                files = set(Path(p.file_path).name for p in successful)
                message = (f"autosec-fix: remediate {len(successful)} vulnerabilities\\n\\n"
                           f"Files: {', '.join(sorted(files)[:5])}")
            result = subprocess.run(["git", "commit", "-m", message],
                                     cwd=str(self.repo_root), capture_output=True,
                                     text=True, timeout=10)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def _resolve_file_path(self, file_path: str) -> Path:
        path = Path(file_path)
        if path.is_absolute():
            return path
        if self.repo_root:
            return self.repo_root / path
        return path

    def _create_backup(self, file_path: Path) -> str:
        backup = file_path.with_suffix(file_path.suffix + self.backup_suffix)
        shutil.copy2(str(file_path), str(backup))
        return str(backup)

    def _apply_replacement(self, content: str, original_block: str,
                           patched_block: str, line_start: int, line_end: int) -> Optional[str]:
        lines = content.split("\\n")
        block_lines = original_block.split("\\n")
        block_len = len(block_lines)
        start_idx = line_start - 1
        if start_idx >= 0 and start_idx + block_len <= len(lines):
            candidate = "\\n".join(lines[start_idx:start_idx + block_len])
            if self._blocks_match(candidate, original_block):
                new = lines[:start_idx] + patched_block.split("\\n") + lines[start_idx + block_len:]
                return "\\n".join(new)
        for i in range(len(lines) - block_len + 1):
            candidate = "\\n".join(lines[i:i + block_len])
            if self._blocks_match(candidate, original_block):
                new = lines[:i] + patched_block.split("\\n") + lines[i + block_len:]
                return "\\n".join(new)
        return None

    def _blocks_match(self, candidate: str, target: str) -> bool:
        if candidate == target:
            return True
        return self._normalize_ws(candidate) == self._normalize_ws(target)

    def _normalize_ws(self, code: str) -> str:
        lines = [l.rstrip().replace("\\t", "    ") for l in code.split("\\n")]
        return "\\n".join(lines).strip()

    def _generate_diff(self, original: List[str], patched: List[str],
                       file_path: str, vuln: Vulnerability) -> str:
        ts = datetime.utcnow().isoformat()
        diff = difflib.unified_diff(original, patched,
                                     fromfile=f"a/{file_path}", tofile=f"b/{file_path}",
                                     fromfiledate=ts, tofiledate=ts, lineterm="")
        header = (f"# AutoSec-Fixer Patch\\n# Vuln: {vuln.rule_id or 'N/A'}\\n"
                  f"# CWE: {vuln.cwe_id or 'N/A'}\\n# Severity: {vuln.severity}\\n"
                  f"# File: {file_path}\\n# Generated: {ts}\\n")
        return header + "\\n".join(diff)
`;

export const mainCode = `"""
main.py - AutoSec-Fixer CLI Entry Point
========================================

Autonomous AI Security Remediation Agent - End-to-end pipeline.

Usage:
    python main.py --report semgrep_results.json --repo /path/to/codebase
    python main.py --report bandit_output.json --repo ./myproject --dry-run
    python main.py --report findings.sarif --repo /code --provider anthropic

Author: AutoSec-Fixer Team
License: MIT
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import List, Optional, Tuple

from ingest import VulnerabilityIngestor, VulnerabilityReport, IngestionError
from context import ContextExtractor, CodeContext, ContextExtractionError
from agent import (SecurityRemediationAgent, OpenAIProvider, AnthropicProvider,
                   AgentResult, AgentState)
from patch import PatchApplier, PatchResult, PatchSet

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("autosec-fixer")


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="autosec-fixer",
        description="AutoSec-Fixer: Autonomous AI Security Remediation Agent.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("Examples:\\n"
                "  %(prog)s --report semgrep.json --repo ./myproject\\n"
                "  %(prog)s --report bandit.json --repo /code --dry-run\\n"
                "  %(prog)s --report findings.sarif --repo ./app --severity HIGH"))
    parser.add_argument("--report", "-r", required=True,
                        help="Path to vulnerability report (SARIF or JSON)")
    parser.add_argument("--repo", "-p", required=True,
                        help="Path to source code repository")
    parser.add_argument("--provider", choices=["openai", "anthropic"], default="openai",
                        help="LLM provider (default: openai)")
    parser.add_argument("--model", default=None, help="Specific model to use")
    parser.add_argument("--api-key", default=None, help="API key (or use env var)")
    parser.add_argument("--severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                        default=None, help="Minimum severity threshold")
    parser.add_argument("--max-vulns", type=int, default=None,
                        help="Maximum vulnerabilities to process")
    parser.add_argument("--file-filter", default=None,
                        help="Only process files matching this pattern")
    parser.add_argument("--dry-run", action="store_true",
                        help="Generate patches without modifying files")
    parser.add_argument("--output-dir", default="./autosecfix_output",
                        help="Output directory for diffs and patches")
    parser.add_argument("--no-backup", action="store_true",
                        help="Skip creating backup files")
    parser.add_argument("--git-commit", action="store_true",
                        help="Create Git commit after patching")
    parser.add_argument("--context-lines", type=int, default=20,
                        help="Context lines above/below (default: 20)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Debug logging")
    parser.add_argument("--quiet", "-q", action="store_true", help="Suppress output")
    return parser.parse_args()


def setup_logging(verbose: bool = False, quiet: bool = False) -> None:
    if quiet:
        level = logging.ERROR
    elif verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO
    logging.getLogger().setLevel(level)


def get_api_key(provider: str, explicit_key: Optional[str] = None) -> str:
    if explicit_key:
        return explicit_key
    env_var = {"openai": "OPENAI_API_KEY", "anthropic": "ANTHROPIC_API_KEY"}.get(provider, "")
    key = os.environ.get(env_var)
    if not key:
        logger.error(f"No API key. Set {env_var} or use --api-key")
        sys.exit(1)
    return key


def create_provider(args: argparse.Namespace):
    api_key = get_api_key(args.provider, args.api_key)
    if args.provider == "openai":
        return OpenAIProvider(api_key=api_key, model=args.model or "gpt-4-turbo-preview")
    elif args.provider == "anthropic":
        return AnthropicProvider(api_key=api_key, model=args.model or "claude-3-opus-20240229")
    else:
        sys.exit(1)


def filter_vulnerabilities(report: VulnerabilityReport, args: argparse.Namespace) -> List:
    vulns = report.vulnerabilities
    if args.severity:
        vulns = report.filter_by_severity(args.severity)
    if args.file_filter:
        import fnmatch
        vulns = [v for v in vulns if fnmatch.fnmatch(v.file_path, args.file_filter)]
    if args.max_vulns:
        vulns = vulns[:args.max_vulns]
    return vulns


def run_pipeline(args: argparse.Namespace) -> int:
    """Execute the end-to-end remediation pipeline."""
    start_time = time.time()
    logger.info("=" * 60)
    logger.info("AutoSec-Fixer - Autonomous Security Remediation")
    logger.info("=" * 60)
    logger.info(f"Report: {args.report}")
    logger.info(f"Repository: {args.repo}")
    logger.info(f"Provider: {args.provider}")
    logger.info(f"Mode: {'DRY RUN' if args.dry_run else 'LIVE'}")

    # Phase 1: Ingest
    logger.info("\\n[Phase 1] Parsing vulnerability report...")
    ingestor = VulnerabilityIngestor()
    try:
        report = ingestor.parse_file(args.report)
    except (IngestionError, FileNotFoundError) as e:
        logger.error(f"Failed to parse report: {e}")
        return 1
    logger.info(f"  Tool: {report.tool}")
    logger.info(f"  Total: {report.total_count}")
    for sev, vs in report.by_severity.items():
        logger.info(f"  {sev}: {len(vs)}")

    # Phase 2: Filter
    vulnerabilities = filter_vulnerabilities(report, args)
    if not vulnerabilities:
        logger.warning("No vulnerabilities to process after filtering.")
        return 0
    logger.info(f"\\n  Processing {len(vulnerabilities)} vulnerabilities...")

    # Phase 3: LLM Setup
    logger.info("\\n[Phase 2] Initializing LLM provider...")
    provider = create_provider(args)
    agent = SecurityRemediationAgent(provider=provider)

    # Phase 4: Extract context & generate patches
    logger.info("\\n[Phase 3] Analyzing code and generating patches...")
    extractor = ContextExtractor(context_lines=args.context_lines)
    applier = PatchApplier(repo_root=args.repo, create_backups=not args.no_backup)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    results: List[AgentResult] = []
    patches_to_apply: List[Tuple] = []

    for i, vuln in enumerate(vulnerabilities, 1):
        logger.info(f"\\n  [{i}/{len(vulnerabilities)}] {vuln.file_path}:{vuln.line_start}")
        logger.info(f"    Rule: {vuln.rule_id} | CWE: {vuln.cwe_id} | Severity: {vuln.severity}")
        try:
            context = extractor.extract(vuln.file_path, vuln.line_start, vuln.line_end,
                                         repo_root=args.repo)
        except (ContextExtractionError, FileNotFoundError) as e:
            logger.error(f"    Context extraction failed: {e}")
            results.append(AgentResult(vulnerability=vuln, state=AgentState.FAILED, error=str(e)))
            continue

        result = agent.remediate(vuln, context)
        results.append(result)
        if result.patch and result.state == AgentState.COMPLETE:
            logger.info(f"    Patch generated (confidence: {result.patch.confidence})")
            patches_to_apply.append((vuln, result.patch))
        else:
            logger.warning(f"    Patch failed: {result.error}")

    # Phase 5: Apply patches
    if patches_to_apply:
        logger.info(f"\\n[Phase 4] Applying {len(patches_to_apply)} patches...")
        patch_set = applier.apply_batch(patches_to_apply, dry_run=args.dry_run)
        for r in patch_set.patches:
            if r.success and r.diff:
                diff_path = output_dir / f"{Path(r.file_path).stem}.diff"
                diff_path.write_text(r.diff, encoding="utf-8")
        applier.generate_patch_file(patch_set, str(output_dir / "combined.patch"))
        if args.git_commit and not args.dry_run:
            applier.create_git_commit(patch_set)
        logger.info(f"\\n{patch_set.summary}")

    # Summary
    elapsed = time.time() - start_time
    summary = {
        "total_vulnerabilities": len(vulnerabilities),
        "patches_generated": len(patches_to_apply),
        "elapsed_seconds": round(elapsed, 2),
    }
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    logger.info(f"\\nCompleted in {elapsed:.2f}s")
    return 0


def main() -> None:
    args = parse_arguments()
    setup_logging(verbose=args.verbose, quiet=args.quiet)
    try:
        sys.exit(run_pipeline(args))
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=args.verbose)
        sys.exit(1)


if __name__ == "__main__":
    main()
`;

export const requirementsTxt = `# AutoSec-Fixer - Requirements
# ============================

# Core LLM providers
openai>=1.12.0
anthropic>=0.18.0

# LangChain (optional, for advanced orchestration)
langchain>=0.1.0
langchain-openai>=0.0.5
langchain-anthropic>=0.1.1

# Utilities
pydantic>=2.5.0
rich>=13.7.0

# Testing
pytest>=7.4.0
pytest-cov>=4.1.0
pytest-asyncio>=0.23.0

# Type checking
mypy>=1.8.0
types-jsonschema>=4.20.0

# Linting
ruff>=0.2.0
black>=24.1.0
`;
