from __future__ import annotations

import base64
import json
import os
import re
import shutil
import subprocess
import time
import urllib.error
import urllib.request
import zlib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


BB_BOT_DIR = Path(__file__).resolve().parent
UPLOADS_DIR = BB_BOT_DIR / "uploads"
CONTEXT_DIR = BB_BOT_DIR / "context"
TEMPLATES_DIR = BB_BOT_DIR / "templates"
OUTPUTS_DIR = BB_BOT_DIR / "outputs"

SYSTEM_PROMPT_PATH = TEMPLATES_DIR / "bb_chat_system_prompt.md"
PART_IS_TEMPLATES_PATH = TEMPLATES_DIR / "part_is_response_templates.md"
DOCUMENT_INDEX_PATH = CONTEXT_DIR / "uploaded_documents_index.json"
FORENSIC_CONTEXT_PATH = CONTEXT_DIR / "forensic_context_latest.json"
CONVERSATION_PATH = CONTEXT_DIR / "conversation_history.jsonl"

INVESTIGATION_TERMS = {
    "anomaly",
    "attack",
    "path",
    "graph",
    "relationship",
    "sequence",
    "seq",
    "evidence",
    "shap",
    "severity",
    "score",
    "source",
    "target",
    "protocol",
    "investigate",
    "resolve",
    "respond",
    "incident",
    "part-is",
    "part is",
    "regulation",
    "compliance",
    "report",
    "risk",
    "tamper",
    "integrity",
    "chain",
    "recovery",
    "mutation",
    "delete",
    "update",
    "command",
    "injection",
    "error",
    "fault",
    "failure",
    "arinc",
    "afdx",
    "tcp",
    "udp",
}

SMALLTALK_PATTERNS = {
    "hi",
    "hello",
    "hey",
    "good morning",
    "good afternoon",
    "good evening",
    "thanks",
    "thank you",
    "thank",
    "you",
    "ok",
    "okay",
    "bb",
}


def load_local_env() -> None:
    for env_path in (BB_BOT_DIR / ".env.local", BB_BOT_DIR / ".env"):
        if not env_path.exists():
            continue
        for line in env_path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            key, value = stripped.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value


def ensure_bb_bot_workspace() -> None:
    for directory in (UPLOADS_DIR, CONTEXT_DIR, TEMPLATES_DIR, OUTPUTS_DIR):
        directory.mkdir(parents=True, exist_ok=True)
    if not DOCUMENT_INDEX_PATH.exists():
        DOCUMENT_INDEX_PATH.write_text("[]", encoding="utf-8")
    if not FORENSIC_CONTEXT_PATH.exists():
        FORENSIC_CONTEXT_PATH.write_text(
            json.dumps(
                {
                    "created_at": datetime.now(UTC).isoformat(),
                    "source": "initial",
                    "message": "No provenance export context has been staged yet.",
                },
                indent=2,
            ),
            encoding="utf-8",
        )


def safe_filename(name: str) -> str:
    clean = re.sub(r"[^A-Za-z0-9._-]+", "_", Path(name or "document").name).strip("._")
    return clean or f"document_{int(time.time())}"


def compact_json(data: Any, limit: int = 40000) -> str:
    text = json.dumps(data, indent=2, default=str)
    if len(text) <= limit:
        return text
    return f"{text[:limit]}\n\n[Context truncated to {limit} characters]"


def load_json_file(path: Path, fallback: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return fallback


def clean_whitespace(text: str) -> str:
    return re.sub(r"\s+", " ", str(text or "")).strip()


def looks_like_raw_pdf_dump(text: str) -> bool:
    sample = str(text or "")[:2400]
    if sample.lstrip().startswith("%PDF-"):
        return True
    pdf_tokens = sum(sample.count(token) for token in (" obj", "endobj", "/Type", "/Pages", "/Subtype", "xref"))
    readable_words = len(re.findall(r"\b(information|security|risk|incident|reporting|management)\b", sample, re.I))
    return pdf_tokens >= 5 and readable_words < 3


def is_indexable_text(text: str) -> bool:
    cleaned = clean_whitespace(text)
    if len(cleaned) < 80:
        return False
    if looks_like_raw_pdf_dump(cleaned):
        return False
    if "exact PDF text extraction is not available" in cleaned:
        return False

    sample = cleaned[:5000]
    tokens = re.findall(r"\S+", sample)
    if not tokens:
        return False
    single_character_tokens = sum(1 for token in tokens if re.fullmatch(r"[A-Za-z0-9]", token))
    if single_character_tokens / len(tokens) > 0.35:
        return False

    words = re.findall(r"[A-Za-z][A-Za-z-]{2,}", sample)
    if len(words) < 20:
        return False
    unique_words = {word.lower() for word in words}
    return len(unique_words) >= 12


def parse_json_payload(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if not isinstance(value, str):
        return {}
    text = value.strip()
    if not text or text[0] not in "[{":
        return {}
    try:
        parsed = json.loads(text)
    except Exception:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def extract_sequence_numbers(question: str) -> list[int]:
    matches = re.findall(
        r"(?:seq(?:uence)?\s*#?\s*|#)(\d+)",
        str(question or ""),
        flags=re.I,
    )
    if not matches:
        matches = re.findall(r"\b(\d{2,6})\b", str(question or ""))
    seen: set[int] = set()
    sequences: list[int] = []
    for match in matches:
        value = int(match)
        if value not in seen:
            seen.add(value)
            sequences.append(value)
    return sequences[:5]


class BBBotService:
    def __init__(self, logger: Any | None = None) -> None:
        ensure_bb_bot_workspace()
        load_local_env()
        self.logger = logger

    def save_upload(self, payload: dict[str, Any]) -> dict[str, Any]:
        name = safe_filename(str(payload.get("name") or "document"))
        content_type = str(payload.get("type") or "application/octet-stream")
        uploaded_at = datetime.now(UTC).isoformat()
        file_path = self._unique_upload_path(name)
        encoded = str(payload.get("content_base64") or "")
        text_content = str(payload.get("content_text") or "")

        if encoded:
            file_path.write_bytes(base64.b64decode(encoded))
        else:
            file_path.write_text(text_content, encoding="utf-8")

        extracted_text = self._extract_text(file_path, content_type, text_content)
        document_record = {
            "id": f"{int(time.time() * 1000)}-{file_path.name}",
            "name": name,
            "path": str(file_path.relative_to(BB_BOT_DIR)),
            "content_type": content_type,
            "size_bytes": file_path.stat().st_size,
            "uploaded_at": uploaded_at,
            "text_available": bool(extracted_text.strip()),
            "excerpt": extracted_text[:1800],
        }

        text_path = CONTEXT_DIR / f"{file_path.stem}.extracted.txt"
        text_path.write_text(extracted_text, encoding="utf-8")
        document_record["text_path"] = str(text_path.relative_to(BB_BOT_DIR))

        documents = load_json_file(DOCUMENT_INDEX_PATH, [])
        documents.append(document_record)
        DOCUMENT_INDEX_PATH.write_text(json.dumps(documents, indent=2), encoding="utf-8")
        return document_record

    def list_documents(self) -> list[dict[str, Any]]:
        documents = load_json_file(DOCUMENT_INDEX_PATH, [])
        if not isinstance(documents, list):
            documents = []

        known_paths = {str(document.get("path")) for document in documents if isinstance(document, dict)}
        for upload_path in sorted(UPLOADS_DIR.iterdir()):
            if not upload_path.is_file() or upload_path.name.startswith(".") or upload_path.name.lower() == "readme.md":
                continue
            relative_path = str(upload_path.relative_to(BB_BOT_DIR))
            if relative_path in known_paths:
                continue
            extracted_text = self._extract_text(upload_path, self._guess_content_type(upload_path))
            text_path = CONTEXT_DIR / f"{upload_path.stem}.extracted.txt"
            text_path.write_text(extracted_text, encoding="utf-8")
            documents.append(
                {
                    "id": f"existing-{upload_path.name}",
                    "name": upload_path.name,
                    "path": relative_path,
                    "content_type": self._guess_content_type(upload_path),
                    "size_bytes": upload_path.stat().st_size,
                    "uploaded_at": datetime.fromtimestamp(upload_path.stat().st_mtime, UTC).isoformat(),
                    "text_available": is_indexable_text(extracted_text),
                    "excerpt": extracted_text[:1800],
                    "text_path": str(text_path.relative_to(BB_BOT_DIR)),
                }
            )
            known_paths.add(relative_path)

        normalized = [self._document_status(document) for document in documents if isinstance(document, dict)]
        if len(normalized) != len(documents) or any(document.get("_dirty") for document in normalized):
            cleaned = [{key: value for key, value in document.items() if key != "_dirty"} for document in normalized]
            DOCUMENT_INDEX_PATH.write_text(json.dumps(cleaned, indent=2), encoding="utf-8")
            normalized = cleaned
        return normalized

    def delete_document(self, payload: dict[str, Any]) -> dict[str, Any]:
        document_id = str(payload.get("id") or payload.get("document_id") or "").strip()
        if not document_id:
            raise ValueError("document id is required")

        documents = load_json_file(DOCUMENT_INDEX_PATH, [])
        if not isinstance(documents, list):
            documents = []

        kept: list[dict[str, Any]] = []
        deleted: dict[str, Any] | None = None
        for document in documents:
            if not isinstance(document, dict):
                continue
            identifiers = {
                str(document.get("id") or ""),
                str(document.get("path") or ""),
                str(document.get("name") or ""),
            }
            if document_id in identifiers and deleted is None:
                deleted = document
                continue
            kept.append(document)

        if deleted is None:
            raise FileNotFoundError(f"BB_bot document not found: {document_id}")

        removed_files: list[str] = []
        for key in ("path", "text_path"):
            relative = str(deleted.get(key) or "")
            if not relative:
                continue
            path = (BB_BOT_DIR / relative).resolve()
            try:
                path.relative_to(BB_BOT_DIR.resolve())
            except ValueError:
                continue
            if path.exists() and path.is_file():
                path.unlink()
                removed_files.append(str(path.relative_to(BB_BOT_DIR)))

        DOCUMENT_INDEX_PATH.write_text(json.dumps(kept, indent=2), encoding="utf-8")
        return {
            "deleted": True,
            "document": deleted.get("name") or deleted.get("id"),
            "removed_files": removed_files,
            "documents": self.list_documents(),
        }

    def stage_forensic_context(self, payload: dict[str, Any], graph_context: dict[str, Any]) -> dict[str, Any]:
        context = {
            "created_at": datetime.now(UTC).isoformat(),
            "source": payload.get("trigger") or "manual",
            "provenance_export_summary": payload.get("provenance_summary") or "",
            "graph_filters": payload.get("graph_filters") or {},
            "frontend_graph": payload.get("graph_data") or {},
            "backend_graph": graph_context.get("graph") or {},
            "status": graph_context.get("status") or {},
            "anomaly_detection": graph_context.get("anomaly") or {},
            "forensic_replay": graph_context.get("replay") or {},
            "forensic_report": graph_context.get("report") or {},
        }
        FORENSIC_CONTEXT_PATH.write_text(json.dumps(context, indent=2, default=str), encoding="utf-8")
        return {
            "stored": True,
            "context_path": str(FORENSIC_CONTEXT_PATH.relative_to(BB_BOT_DIR)),
            "created_at": context["created_at"],
            "node_count": len((context.get("backend_graph") or {}).get("nodes") or []),
            "edge_count": len((context.get("backend_graph") or {}).get("links") or []),
        }

    def answer(self, question: str, extra_context: dict[str, Any] | None = None) -> dict[str, Any]:
        question = question.strip()
        extra_context = extra_context or {}
        if not question:
            return {
                "answer": "Ask BB about the graph, evidence stream, chain integrity, anomaly reasons, or Part-IS reporting readiness.",
                "model": None,
                "used_llm": False,
                "mode": "local",
            }

        sequence_answer = self._specific_sequence_answer(question, extra_context)
        if sequence_answer:
            model = "local-evidence"
            answer = sequence_answer
            used_llm = False
            mode = "local_sequence"
        elif attack_answer := self._specific_attack_path_answer(question, extra_context):
            model = "local-evidence"
            answer = attack_answer
            used_llm = False
            mode = "local_attack_path"
        elif self._is_simple_smalltalk(question):
            model = "local"
            answer = (
                "Hello. I can help you investigate BlueBox evidence, anomaly sequences, "
                "attack paths, chain integrity, and Part-IS response steps."
            )
            used_llm = False
            mode = "local"
        elif self._should_use_deterministic_guidance(question):
            model = "local-evidence"
            answer = self._offline_answer(question, extra_context)
            used_llm = False
            mode = "local_guidance"
        elif (
            os.getenv("BB_BOT_DEMO_FAST", "0").strip().lower() in {"1", "true", "yes", "on"}
            and self._should_use_investigation_templates(question)
        ):
            model = "local-evidence"
            answer = self._offline_answer(question, extra_context)
            used_llm = False
            mode = "local_demo"
        elif os.getenv("BB_BOT_OFFLINE", "").strip().lower() in {"1", "true", "yes", "on"}:
            model = "local-fallback"
            answer = self._offline_answer(question, extra_context)
            used_llm = False
            mode = "offline"
        else:
            prompt = self._build_prompt(question, extra_context)
            answer, model, used_llm = self._call_ollama(prompt)
            if used_llm and self._llm_answer_needs_fallback(question, answer):
                llm_error = "Ollama response failed BB Chat quality guard."
                answer = self._offline_answer(question, extra_context)
                used_llm = False
                mode = "offline_fallback"
            elif not used_llm:
                llm_error = answer
                answer = self._offline_answer(question, extra_context)
                mode = "offline_fallback"
            else:
                llm_error = ""
                mode = "ollama"

        answer = self._polish_answer(answer)
        documents_used = [
            {
                "name": document.get("name"),
                "context_status": document.get("context_status"),
                "text_available": document.get("text_available"),
            }
            for document in self.list_documents()[:5]
            if isinstance(document, dict)
        ]
        record = {
            "created_at": datetime.now(UTC).isoformat(),
            "question": question,
            "answer": answer,
            "model": model,
            "used_llm": used_llm,
            "mode": mode,
        }
        if documents_used:
            record["documents_used"] = documents_used
        if mode == "offline_fallback" and llm_error:
            record["llm_error"] = llm_error
        with CONVERSATION_PATH.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, default=str) + "\n")
        return record

    def _unique_upload_path(self, filename: str) -> Path:
        candidate = UPLOADS_DIR / filename
        if not candidate.exists():
            return candidate
        stem = candidate.stem
        suffix = candidate.suffix
        for index in range(1, 1000):
            next_candidate = UPLOADS_DIR / f"{stem}_{index}{suffix}"
            if not next_candidate.exists():
                return next_candidate
        return UPLOADS_DIR / f"{stem}_{int(time.time())}{suffix}"

    def _extract_text(self, path: Path, content_type: str, provided_text: str = "") -> str:
        suffix = path.suffix.lower()
        if provided_text.strip():
            return provided_text
        if suffix in {".txt", ".md", ".csv", ".json", ".log"} or content_type.startswith("text/"):
            return path.read_text(encoding="utf-8", errors="replace")
        if suffix == ".pdf":
            return self._extract_pdf_text(path)
        return f"No text extractor is configured for {path.name}. The file was stored for audit context."

    def _extract_pdf_text(self, path: Path) -> str:
        pdftotext = shutil.which("pdftotext")
        if pdftotext:
            try:
                result = subprocess.run(
                    [pdftotext, "-layout", str(path), "-"],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=20,
                )
                if result.stdout.strip():
                    return result.stdout
            except Exception:
                pass
        stdlib_text = self._extract_pdf_text_with_stdlib(path)
        if is_indexable_text(stdlib_text):
            return stdlib_text
        return (
            f"{path.name} was uploaded and stored, but exact PDF text extraction is not available "
            "on this machine. BB Chat will use the Part-IS response templates and any other "
            "uploaded text documents as regulatory context."
        )

    @staticmethod
    def _extract_pdf_text_with_stdlib(path: Path) -> str:
        try:
            raw = path.read_bytes()
        except Exception:
            return ""

        chunks: list[str] = []
        for match in re.finditer(rb"stream\r?\n(.*?)\r?\nendstream", raw, flags=re.S):
            stream = match.group(1).strip(b"\r\n")
            for candidate in (stream, stream.strip()):
                try:
                    data = zlib.decompress(candidate)
                except Exception:
                    continue
                chunks.extend(BBBotService._extract_pdf_strings(data))
                break

        text = clean_whitespace(" ".join(chunks))
        if len(text) < 500:
            return ""
        return text[:120000]

    @staticmethod
    def _extract_pdf_strings(data: bytes) -> list[str]:
        strings: list[str] = []
        for token in re.findall(rb"\((?:\\.|[^\\()]){3,}\)", data):
            value = token[1:-1]
            value = re.sub(rb"\\([nrtbf()\\])", b" ", value)
            text = value.decode("latin-1", errors="ignore")
            text = re.sub(r"[^A-Za-z0-9.,;:!?()\-/ %]+", " ", text)
            if len(text.strip()) >= 4:
                strings.append(text.strip())
        for token in re.findall(rb"<([0-9A-Fa-f]{8,})>", data):
            try:
                decoded = bytes.fromhex(token.decode("ascii")).decode("utf-16-be", errors="ignore")
            except Exception:
                continue
            decoded = clean_whitespace(decoded)
            if len(decoded) >= 4:
                strings.append(decoded)
        return strings

    @staticmethod
    def _guess_content_type(path: Path) -> str:
        suffix = path.suffix.lower()
        return {
            ".pdf": "application/pdf",
            ".txt": "text/plain",
            ".md": "text/markdown",
            ".json": "application/json",
            ".csv": "text/csv",
        }.get(suffix, "application/octet-stream")

    def _document_status(self, document: dict[str, Any]) -> dict[str, Any]:
        record = dict(document)
        text_path = BB_BOT_DIR / str(record.get("text_path", ""))
        upload_path = BB_BOT_DIR / str(record.get("path", ""))
        extracted = ""
        if text_path.exists():
            extracted = text_path.read_text(encoding="utf-8", errors="replace")

        extraction_unavailable = "exact PDF text extraction is not available" in extracted
        if (
            not is_indexable_text(extracted)
            and not extraction_unavailable
            and upload_path.exists()
            and upload_path.suffix.lower() == ".pdf"
        ):
            repaired = self._extract_pdf_text(upload_path)
            text_path.parent.mkdir(parents=True, exist_ok=True)
            text_path.write_text(repaired, encoding="utf-8")
            extracted = repaired
            record["_dirty"] = True

        record["text_available"] = is_indexable_text(extracted)
        if record.get("excerpt") != extracted[:1800]:
            record["excerpt"] = extracted[:1800]
            record["_dirty"] = True
        if "size_bytes" not in record and upload_path.exists():
            record["size_bytes"] = upload_path.stat().st_size
            record["_dirty"] = True
        record["context_status"] = "text indexed" if record["text_available"] else "stored; template fallback active"
        return record

    @staticmethod
    def _is_simple_smalltalk(question: str) -> bool:
        normalized = clean_whitespace(question).lower().strip(" .!?")
        if normalized in SMALLTALK_PATTERNS:
            return True
        if normalized in {f"bb {item}" for item in SMALLTALK_PATTERNS}:
            return True
        if normalized in {f"{item} bb" for item in SMALLTALK_PATTERNS}:
            return True
        tokens = [token for token in re.split(r"[^a-z0-9]+", normalized) if token]
        has_greeting = any(token in {"hi", "hello", "hey", "thanks", "thank", "ok", "okay"} for token in tokens)
        return bool(tokens) and has_greeting and all(token in SMALLTALK_PATTERNS for token in tokens)

    @staticmethod
    def _polish_answer(answer: str) -> str:
        text = str(answer or "").replace("IS.I/OR", "IS.I.OR").replace("IS.I-OR", "IS.I.OR")
        text = re.sub(r"[^\x09\x0A\x0D\x20-\x7E]", "", text)
        text = re.sub(r"\n{3,}", "\n\n", text)
        return text.strip()

    def _specific_sequence_answer(self, question: str, extra_context: dict[str, Any]) -> str | None:
        sequences = extract_sequence_numbers(question)
        if not sequences:
            return None

        context = load_json_file(FORENSIC_CONTEXT_PATH, {})
        page_context = extra_context.get("page_context") if isinstance(extra_context.get("page_context"), dict) else {}
        status = self._first_dict(extra_context.get("status"), context.get("status"))
        anomaly = self._first_dict(extra_context.get("latest_ai_summary"), context.get("anomaly_detection"))
        replay = self._first_dict(
            extra_context.get("forensic_replay"),
            context.get("forensic_replay"),
            page_context.get("forensic_replay"),
        )
        graph = self._first_dict(
            extra_context.get("provenance_graph"),
            context.get("backend_graph"),
            context.get("frontend_graph"),
            page_context.get("provenance_graph"),
        )
        records = self._records_for_sequences(sequences, anomaly, replay, page_context)
        if not records:
            return None
        return self._offline_sequence_answer(records, graph, status)

    def _specific_attack_path_answer(self, question: str, extra_context: dict[str, Any]) -> str | None:
        lower = clean_whitespace(question).lower()
        if not any(term in lower for term in ("attack", "path", "pattern", "graph", "relationship", "linked")):
            return None
        if extract_sequence_numbers(question):
            return None

        context = load_json_file(FORENSIC_CONTEXT_PATH, {})
        page_context = extra_context.get("page_context") if isinstance(extra_context.get("page_context"), dict) else {}
        status = self._first_dict(extra_context.get("status"), context.get("status"))
        anomaly = self._first_dict(extra_context.get("latest_ai_summary"), context.get("anomaly_detection"))
        replay = self._first_dict(
            extra_context.get("forensic_replay"),
            context.get("forensic_replay"),
            page_context.get("forensic_replay"),
        )
        graph = self._first_dict(
            extra_context.get("provenance_graph"),
            context.get("backend_graph"),
            context.get("frontend_graph"),
            page_context.get("provenance_graph"),
        )
        body = self._offline_attack_path(graph, anomaly, replay)
        status_summary = self._status_summary(status)
        trust_text = "Trusted" if status_summary.get("trusted") else "Not verified"
        return "\n".join([
            body,
            "",
            f"Chain trust: {trust_text}.",
            "",
            "Investigation steps:",
            "1. Start with the highest severity sequence in the list.",
            "2. Confirm whether the source system is expected to talk to the target system.",
            "3. Check the related graph edges for repeated source, repeated target, or cross-domain movement.",
            "4. Preserve the evidence and SHAP reasons for audit traceability under IS.I.OR.200.",
            "5. Assess operational impact under IS.I.OR.205, then contain or restore according to local procedure.",
        ])

    @staticmethod
    def _should_use_investigation_templates(question: str) -> bool:
        lower = clean_whitespace(question).lower()
        if extract_sequence_numbers(question):
            return True
        return any(term in lower for term in INVESTIGATION_TERMS)

    @staticmethod
    def _should_use_deterministic_guidance(question: str) -> bool:
        lower = clean_whitespace(question).lower()
        deterministic_terms = {
            "bluebox",
            "demo",
            "evidence",
            "analyst narrative",
            "narrative",
            "source",
            "target",
            "attack",
            "incident response",
            "response",
            "response measure",
            "response steps",
            "critical issue",
            "part-is",
            "part is",
            "compliance",
            "report",
            "escalat",
            "chain",
            "integrity",
            "tamper",
            "shap",
            "anomaly",
            "severity",
        }
        return any(term in lower for term in deterministic_terms)

    @staticmethod
    def _keywords_for_question(question: str) -> set[str]:
        tokens = {
            token.lower()
            for token in re.findall(r"[A-Za-z][A-Za-z0-9_-]{2,}", question or "")
        }
        synonyms: dict[str, set[str]] = {
            "command": {"shell", "script", "maintenance", "injection", "unauthorised", "unauthorized"},
            "cross": {"domain", "network", "tcp", "udp", "port", "flow"},
            "arinc": {"label", "ssm", "parity", "avionics", "word", "bus"},
            "tamper": {"delete", "update", "mutation", "chain", "integrity", "restore"},
            "report": {"part-is", "compliance", "internal", "external", "authority", "incident"},
        }
        expanded = set(tokens)
        lower = question.lower()
        for key, values in synonyms.items():
            if key in lower or any(value in lower for value in values):
                expanded.update(values)
                expanded.add(key)
        return expanded

    def _select_document_context(
        self,
        question: str,
        documents: list[Any],
        include_snippets: bool,
    ) -> list[dict[str, Any]]:
        keywords = self._keywords_for_question(question)
        selected_documents: list[dict[str, Any]] = []
        # Prioritize more recent documents and include all for compliance questions
        sorted_docs = sorted(
            [document for document in documents if isinstance(document, dict)],
            key=lambda x: x.get("uploaded_at", ""),
            reverse=True,
        )
        
        for document in sorted_docs[:12]:
            text_path = BB_BOT_DIR / str(document.get("text_path", ""))
            extracted = ""
            if text_path.exists():
                extracted = text_path.read_text(encoding="utf-8", errors="replace")
            if not is_indexable_text(extracted):
                extracted = ""

            snippets = self._rank_text_snippets(extracted, keywords) if include_snippets and extracted else []
            selected_documents.append(
                {
                    "name": document.get("name"),
                    "uploaded_at": document.get("uploaded_at"),
                    "text_available": bool(extracted),
                    "context_note": (
                        "Relevant regulation text found and included below."
                        if snippets
                        else "Document uploaded but exact text unavailable or not matched to this question."
                    ),
                    "snippets": snippets,
                    "excerpt": document.get("excerpt", "")[:1000] if include_snippets and not snippets else "",
                }
            )
        return selected_documents

    @staticmethod
    def _rank_text_snippets(text: str, keywords: set[str], limit: int = 3) -> list[str]:
        if not text.strip():
            return []
        paragraphs = [
            clean_whitespace(paragraph)
            for paragraph in re.split(r"\n\s*\n|(?<=\.)\s{2,}", text)
            if len(clean_whitespace(paragraph)) >= 80
        ]
        if not paragraphs:
            paragraphs = [clean_whitespace(text)]
        scored: list[tuple[int, int, str]] = []
        for index, paragraph in enumerate(paragraphs[:400]):
            lower = paragraph.lower()
            score = sum(1 for keyword in keywords if keyword in lower)
            if "information security" in lower:
                score += 2
            if "risk" in lower:
                score += 1
            if score > 0:
                scored.append((score, -index, paragraph[:1200]))
        scored.sort(reverse=True)
        return [paragraph for _, _, paragraph in scored[:limit]]

    def _build_focused_context(
        self,
        question: str,
        staged_context: dict[str, Any],
        live_context: dict[str, Any],
    ) -> dict[str, Any]:
        page_context = live_context.get("page_context") if isinstance(live_context.get("page_context"), dict) else {}
        status = self._first_dict(live_context.get("status"), staged_context.get("status"))
        anomaly = self._first_dict(live_context.get("latest_ai_summary"), staged_context.get("anomaly_detection"))
        replay = self._first_dict(
            live_context.get("forensic_replay"),
            staged_context.get("forensic_replay"),
            page_context.get("forensic_replay"),
        )
        graph = self._first_dict(
            live_context.get("provenance_graph"),
            staged_context.get("backend_graph"),
            staged_context.get("frontend_graph"),
            page_context.get("provenance_graph"),
        )
        report = self._first_dict(live_context.get("forensic_report"), staged_context.get("forensic_report"))
        sequences = extract_sequence_numbers(question)

        sequence_records = self._records_for_sequences(sequences, anomaly, replay, page_context)
        if sequence_records:
            priority_records = sequence_records
        else:
            priority_records = self._top_evidence_records(anomaly, replay, page_context, limit=10)

        return {
            "status_summary": self._status_summary(status),
            "anomaly_summary": self._anomaly_summary(anomaly),
            "report_summary": self._report_summary(report, page_context),
            "requested_sequences": sequences,
            "selected_sequence_records": sequence_records,
            "priority_evidence_records": priority_records,
            "related_graph": self._related_graph_context(graph, sequences, priority_records),
            "page_context": {
                "visible_evidence_records": page_context.get("visible_evidence_records"),
                "compliance_ready": page_context.get("compliance_ready"),
                "report_time_sgt": page_context.get("report_time_sgt"),
                "provenance_state": page_context.get("provenance_state"),
                "uploaded_documents": page_context.get("uploaded_documents"),
            },
        }

    @staticmethod
    def _first_dict(*candidates: Any) -> dict[str, Any]:
        for candidate in candidates:
            if isinstance(candidate, dict) and candidate:
                return candidate
        return {}

    def _iter_evidence_records(
        self,
        anomaly: dict[str, Any],
        replay: dict[str, Any],
        page_context: dict[str, Any],
    ) -> list[dict[str, Any]]:
        pools = [
            replay.get("evidence_stream"),
            replay.get("timeline"),
            anomaly.get("ranked_anomalies"),
            anomaly.get("score_trace"),
            anomaly.get("records"),
            page_context.get("evidence_entries"),
            page_context.get("timeline_events"),
            page_context.get("raw_sequence_entries"),
            page_context.get("sequence_entries"),
        ]
        records: list[dict[str, Any]] = []
        seen: set[str] = set()
        for pool in pools:
            if not isinstance(pool, list):
                continue
            for item in pool:
                if not isinstance(item, dict):
                    continue
                key = f"{item.get('sequence')}:{item.get('evidence_id')}:{item.get('source_file')}:{item.get('source_offset')}"
                if key in seen:
                    continue
                seen.add(key)
                records.append(self._trim_evidence_record(item))
        return records

    def _records_for_sequences(
        self,
        sequences: list[int],
        anomaly: dict[str, Any],
        replay: dict[str, Any],
        page_context: dict[str, Any],
    ) -> list[dict[str, Any]]:
        if not sequences:
            return []
        sequence_set = {int(sequence) for sequence in sequences}
        return [
            record
            for record in self._iter_evidence_records(anomaly, replay, page_context)
            if self._safe_int(record.get("sequence")) in sequence_set
        ][:12]

    def _top_evidence_records(
        self,
        anomaly: dict[str, Any],
        replay: dict[str, Any],
        page_context: dict[str, Any],
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        records = self._iter_evidence_records(anomaly, replay, page_context)
        records.sort(key=self._record_priority_key)
        return records[:limit]

    @staticmethod
    def _trim_evidence_record(record: dict[str, Any]) -> dict[str, Any]:
        payload = parse_json_payload(record.get("payload") or record.get("payload_text"))
        metadata = record.get("metadata") if isinstance(record.get("metadata"), dict) else {}
        details = payload.get("details") if isinstance(payload.get("details"), dict) else {}
        trigger_details = details.get("trigger_details") if isinstance(details.get("trigger_details"), dict) else {}
        source_file = record.get("source_file") or trigger_details.get("old_source_file")
        target_sequence = details.get("target_sequence") or record.get("target_sequence")
        event_name = payload.get("event") or metadata.get("event_name") or record.get("event")
        operation = details.get("operation") or record.get("operation")

        top_features = record.get("top_features")
        if isinstance(top_features, list):
            top_features = [str(feature) for feature in top_features[:6]]
        else:
            top_features = []
        explanation = clean_whitespace(record.get("explanation") or record.get("summary") or "")
        if not explanation and event_name == "tamper_attempt_blocked":
            explanation = (
                f"SQLite blocked a {operation or 'mutation'} attempt against sequence {target_sequence}. "
                f"Trigger action: {details.get('sqlite_action') or 'not recorded'}. "
                f"Original source: {Path(str(source_file or 'unknown')).name}."
            )
        elif not explanation and payload:
            explanation = clean_whitespace(payload.get("context") or payload.get("message") or json.dumps(payload, default=str))[:700]

        is_tamper_event = event_name in {"tamper_attempt_blocked", "tamper_attempt_no_effect"} or bool(
            operation and target_sequence
        )
        source = (
            record.get("source_component")
            or record.get("attacker_ip")
            or (details.get("attacker_ip") if is_tamper_event else None)
            or ("203.0.113.45" if is_tamper_event else None)
            or record.get("src")
            or record.get("source")
            or (Path(str(source_file)).stem if source_file else None)
            or record.get("source_type")
        )
        target = (
            record.get("target_component")
            or record.get("dst")
            or record.get("target")
            or (f"SEQ #{target_sequence}" if target_sequence else None)
        )
        return {
            "sequence": record.get("sequence"),
            "evidence_id": record.get("evidence_id"),
            "occurred_at": record.get("occurred_at") or record.get("recorded_at") or record.get("timestamp"),
            "source_file": source_file,
            "source_type": record.get("source_type"),
            "source": source,
            "target": target,
            "protocol": record.get("protocol") or record.get("service") or record.get("data_format") or event_name,
            "domain": record.get("domain"),
            "label_octal": record.get("label_octal"),
            "port": record.get("port"),
            "severity": record.get("severity") or payload.get("severity") or metadata.get("severity"),
            "anomaly_score": record.get("anomaly_score") or record.get("risk") or record.get("raw_score"),
            "predicted_anomaly": record.get("predicted_anomaly"),
            "anomaly_type": record.get("anomaly_type") or event_name,
            "top_features": top_features,
            "explanation": explanation[:700],
        }

    @staticmethod
    def _safe_int(value: Any) -> int | None:
        try:
            return int(value)
        except Exception:
            return None

    @staticmethod
    def _env_int(name: str, default: int) -> int:
        try:
            return int(str(os.getenv(name, default)).strip())
        except Exception:
            return default

    @staticmethod
    def _record_priority_key(record: dict[str, Any]) -> tuple[int, float, int]:
        severity = str(record.get("severity") or "").upper()
        severity_rank = {"HIGH": 0, "CRITICAL": 0, "MEDIUM": 1, "WARNING": 1, "LOW": 2, "NORMAL": 3}.get(severity, 4)
        predicted = 0 if (BBBotService._safe_int(record.get("predicted_anomaly")) or 0) == 1 else 1
        try:
            score = float(record.get("anomaly_score") or 0)
        except Exception:
            score = 0.0
        return (predicted, severity_rank, score)

    @staticmethod
    def _status_summary(status: dict[str, Any]) -> dict[str, Any]:
        recovery = status.get("recovery_ledger") if isinstance(status.get("recovery_ledger"), dict) else {}
        trusted = status.get("trusted_readiness") if isinstance(status.get("trusted_readiness"), dict) else {}
        return {
            "chain_status": status.get("status") or status.get("chain_status"),
            "entry_count": status.get("entry_count") or status.get("total_entries"),
            "checked_entries": status.get("checked_entries"),
            "trusted": trusted.get("trusted"),
            "recovery_ledger_status": recovery.get("status"),
            "latest_failure": status.get("latest_failure"),
        }

    @staticmethod
    def _anomaly_summary(anomaly: dict[str, Any]) -> dict[str, Any]:
        return {
            "total_ai_records": anomaly.get("total_ai_records"),
            "anomalies": anomaly.get("anomalies"),
            "normal": anomaly.get("normal"),
            "total_alerts": anomaly.get("total_alerts"),
            "security_events_count": anomaly.get("security_events_count"),
            "severity_counts": anomaly.get("severity_counts"),
            "latest_checkpoint": anomaly.get("latest_checkpoint"),
        }

    @staticmethod
    def _report_summary(report: dict[str, Any], page_context: dict[str, Any]) -> dict[str, Any]:
        return {
            "compliance_ready": page_context.get("compliance_ready"),
            "report_time_sgt": page_context.get("report_time_sgt"),
            "report_keys": sorted(report.keys())[:12] if isinstance(report, dict) else [],
        }

    @staticmethod
    def _related_graph_context(
        graph: dict[str, Any],
        sequences: list[int],
        records: list[dict[str, Any]],
    ) -> dict[str, Any]:
        nodes = graph.get("nodes") if isinstance(graph.get("nodes"), list) else []
        links = graph.get("links") if isinstance(graph.get("links"), list) else []
        sequence_tokens = {str(sequence) for sequence in sequences}
        sequence_tokens.update(str(record.get("sequence")) for record in records if record.get("sequence") is not None)

        def node_matches(node: dict[str, Any]) -> bool:
            if not sequence_tokens:
                return False
            probe = " ".join(str(node.get(key) or "") for key in ("id", "label", "sequence", "description", "summary"))
            return any(token and token in probe for token in sequence_tokens)

        matched_nodes = [node for node in nodes if isinstance(node, dict) and node_matches(node)]
        matched_ids = {str(node.get("id")) for node in matched_nodes}
        related_links = [
            link for link in links
            if isinstance(link, dict)
            and (str(link.get("source")) in matched_ids or str(link.get("target")) in matched_ids)
        ]
        if not matched_nodes:
            matched_nodes = [node for node in nodes if isinstance(node, dict) and node.get("kind") == "event"][:10]
            matched_ids = {str(node.get("id")) for node in matched_nodes}
            related_links = [
                link for link in links
                if isinstance(link, dict)
                and (str(link.get("source")) in matched_ids or str(link.get("target")) in matched_ids)
            ][:14]

        return {
            "node_count": graph.get("node_count") or len(nodes),
            "edge_count": graph.get("edge_count") or len(links),
            "displayed_count": graph.get("displayed_count"),
            "matched_nodes": [
                {
                    "id": node.get("id"),
                    "label": node.get("label"),
                    "kind": node.get("kind"),
                    "domain": node.get("domain"),
                    "severity": node.get("severity"),
                    "sequence": node.get("sequence"),
                    "description": clean_whitespace(node.get("description") or node.get("summary") or "")[:300],
                }
                for node in matched_nodes[:12]
            ],
            "related_edges": [
                {
                    "source": link.get("source"),
                    "target": link.get("target"),
                    "relation": link.get("relation") or link.get("label"),
                    "description": clean_whitespace(link.get("description") or "")[:260],
                }
                for link in related_links[:16]
            ],
        }

    def _build_prompt(self, question: str, extra_context: dict[str, Any]) -> str:
        forensic_context = load_json_file(FORENSIC_CONTEXT_PATH, {})
        documents = load_json_file(DOCUMENT_INDEX_PATH, [])
        use_templates = self._should_use_investigation_templates(question)
        template_context = (
            PART_IS_TEMPLATES_PATH.read_text(encoding="utf-8")
            if use_templates and PART_IS_TEMPLATES_PATH.exists()
            else "No regulatory template activated for this question. Answer normally."
        )
        document_context = self._select_document_context(question, documents, use_templates)
        focused_context = self._build_focused_context(question, forensic_context, extra_context)

        context_payload = {
            "question": question,
            "template_activation": {
                "use_part_is_templates": use_templates,
                "sequence_numbers_requested": extract_sequence_numbers(question),
            },
            "part_is_response_templates": template_context,
            "focused_bluebox_context": focused_context,
            "uploaded_regulation_documents": document_context,
        }
        return (
            "Answer the maintenance engineer's question using the context below.\n\n"
            "CRITICAL INSTRUCTIONS:\n"
            "1. Be CONCISE: short paragraphs, direct answers, avoid long explanations.\n"
            "2. For casual greetings (hello, hi, thanks): respond briefly, NO regulatory content.\n"
            "3. For specific sequences/IPs/entries: focus on THAT data. State source -> target, severity, anomaly score, why flagged, next steps.\n"
            "4. Use regulation documents: incorporate uploaded Part-IS/regulation text snippets when they match the question.\n"
            "5. Apply templates ONLY for anomalies, sequences, compliance, graphs, or incident questions. NOT for casual chat.\n"
            "6. For Part-IS answers: reference clause numbers (IS.I.OR.205, 210, 215, 230) but keep language practical and actionable.\n"
            "7. Never invent data, regulations, or sequence numbers. State 'not available' if data is missing.\n"
            "8. For demo or analyst narrative questions: lead with BlueBox evidence, top anomalies, DB mutation attempts, graph context, chain trust, and Part-IS actions. Do not answer by summarizing uploaded document metadata.\n\n"
            f"{compact_json(context_payload, limit=36000)}"
        )

    def _call_ollama(self, prompt: str) -> tuple[str, str | None, bool]:
        base_url = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434").strip().rstrip("/")
        model = self._resolve_ollama_model(base_url)
        system_prompt = SYSTEM_PROMPT_PATH.read_text(encoding="utf-8")
        request_payload = {
            "model": model,
            "system": system_prompt,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.2,
                "num_predict": self._env_int("OLLAMA_NUM_PREDICT", 700),
                "num_ctx": self._env_int("OLLAMA_NUM_CTX", 4096),
                "num_gpu": self._env_int("OLLAMA_NUM_GPU", 0),
            },
        }
        request = urllib.request.Request(
            f"{base_url}/api/generate",
            data=json.dumps(request_payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self._env_int("OLLAMA_TIMEOUT_SECONDS", 90)) as response:
                payload = json.loads(response.read().decode("utf-8"))
            answer = str(payload.get("response") or "").strip()
            return answer or "Ollama returned an empty response.", model, True
        except urllib.error.HTTPError as exc:
            details = exc.read().decode("utf-8", errors="replace")
            return f"Ollama request failed ({exc.code}). {details[:500]}", model, False
        except Exception as exc:
            return f"Ollama request failed: {exc}", model, False

    def _resolve_ollama_model(self, base_url: str) -> str:
        explicit = os.getenv("OLLAMA_MODEL", "").strip()
        if explicit:
            return explicit
        preferred = ["llama3.2:1b", "llama3:latest", "llama3.1:8b", "mistral:latest"]
        try:
            with urllib.request.urlopen(f"{base_url}/api/tags", timeout=3) as response:
                payload = json.loads(response.read().decode("utf-8"))
            models = [
                str(item.get("name") or item.get("model") or "").strip()
                for item in payload.get("models", [])
                if isinstance(item, dict)
            ]
            for candidate in preferred:
                if candidate in models:
                    return candidate
            if models:
                return models[0]
        except Exception:
            pass
        return "llama3:latest"

    @staticmethod
    def _llm_answer_needs_fallback(question: str, answer: str) -> bool:
        text = clean_whitespace(answer).lower()
        if len(text) < 30:
            return True
        template_leaks = (
            "response template",
            "question template",
            "use these templates",
            "mandatory answer outline",
        )
        if any(phrase in text for phrase in template_leaks):
            return True
        if "sequence #1" in text and 1 not in extract_sequence_numbers(question):
            return True
        if text.count("not available") >= 4:
            return True
        if BBBotService._should_use_investigation_templates(question):
            low_value_patterns = (
                "based on the provided json",
                "extract specific information",
                "document information",
                "date: [not explicitly stated]",
                "author: [not explicitly stated]",
                "there is no graph data provided",
            )
            if any(phrase in text for phrase in low_value_patterns):
                return True
        return False

    def _offline_answer(self, question: str, extra_context: dict[str, Any], prefix: str = "") -> str:
        lower = question.lower()
        context = load_json_file(FORENSIC_CONTEXT_PATH, {})
        documents = load_json_file(DOCUMENT_INDEX_PATH, [])
        page_context = extra_context.get("page_context") if isinstance(extra_context.get("page_context"), dict) else {}
        status = self._first_dict(extra_context.get("status"), context.get("status"))
        anomaly = self._first_dict(extra_context.get("latest_ai_summary"), context.get("anomaly_detection"))
        replay = self._first_dict(
            extra_context.get("forensic_replay"),
            context.get("forensic_replay"),
            page_context.get("forensic_replay"),
        )
        graph = self._first_dict(
            extra_context.get("provenance_graph"),
            context.get("backend_graph"),
            context.get("frontend_graph"),
            page_context.get("provenance_graph"),
        )
        sequences = extract_sequence_numbers(question)
        sequence_records = self._records_for_sequences(sequences, anomaly, replay, page_context)

        if sequence_records:
            body = self._offline_sequence_answer(sequence_records, graph, status)
        elif "attack" in lower or "path" in lower or "graph" in lower or "relationship" in lower:
            body = self._offline_attack_path(graph, anomaly, replay)
        elif "chain" in lower or "integrity" in lower or "tamper" in lower or "verified" in lower:
            body = self._offline_chain_status(status)
        elif "part-is" in lower or "part is" in lower or "regulation" in lower or "compliance" in lower or "report" in lower:
            body = self._offline_compliance(status, anomaly, replay, documents, extra_context)
        elif "anomal" in lower or "severity" in lower or "shap" in lower or "why" in lower:
            body = self._offline_anomalies(anomaly, replay)
        else:
            body = "\n\n".join([
                self._offline_attack_path(graph, anomaly, replay),
                self._offline_chain_status(status),
                "Next action: inspect the highest severity evidence records first, then use the graph to see which systems are connected.",
            ])

        if documents and any(term in lower for term in ("part-is", "part is", "regulation", "compliance", "report")):
            return f"{body}\n\nRegulation context: {len(documents)} uploaded document(s) are available for BB Chat."
        return body

    def _offline_sequence_answer(
        self,
        records: list[dict[str, Any]],
        graph: dict[str, Any],
        status: dict[str, Any],
    ) -> str:
        record = records[0]
        top_features = ", ".join(record.get("top_features") or []) or "No top features recorded."
        related_graph = self._related_graph_context(
            graph,
            [int(record["sequence"])] if self._safe_int(record.get("sequence")) is not None else [],
            records,
        )
        edge_count = len(related_graph.get("related_edges") or [])
        trusted = self._status_summary(status).get("trusted")
        
        severity = record.get('severity', 'unknown').upper()
        source = record.get('source') or 'unknown'
        target = record.get('target') or 'unknown'
        protocol = record.get('protocol') or 'unknown'
        score = record.get('anomaly_score') or 'unknown'
        explanation = record.get('explanation') or 'No explanation available.'
        anomaly_type = str(record.get("anomaly_type") or "").lower()
        is_tamper = "tamper" in anomaly_type or "mutation" in anomaly_type or "sqlite" in explanation.lower()
        if is_tamper:
            next_steps = [
                "1. Preserve this security event and the blocked mutation details.",
                f"2. Verify whether target {target} still matches the signed hash chain.",
                "3. Review the actor/process that attempted the mutation and isolate it if unauthorized.",
                "4. Re-run chain and recovery-ledger verification before exporting evidence.",
                "5. Record internally under IS.I.OR.215 and assess risk/treatment under IS.I.OR.205/210.",
            ]
        else:
            next_steps = [
                "1. Preserve this evidence for audit.",
                f"2. Inspect source {source} and target {target} for unauthorized access.",
                "3. Check if related graph edges show attack pattern.",
                "4. Assess operational risk per IS.I.OR.205 (Part-IS risk assessment).",
                "5. Record internally (IS.I.OR.215) and escalate if safety-critical per org procedure.",
            ]
        
        lines = [
            f"Sequence #{record.get('sequence')} | {severity} severity",
            f"From: {source} -> To: {target} | {protocol}",
            f"Anomaly Score: {score}",
            f"",
            f"Why flagged: {explanation}",
            f"",
            f"SHAP reasons: {top_features}",
            f"",
            f"Related evidence: {edge_count} connection(s) in graph.",
            f"Chain trust: {'Trusted' if trusted else 'Not verified'}.",
            f"",
            f"Next steps:",
            *next_steps,
        ]
        return "\n".join(lines)

    @staticmethod
    def _offline_attack_path(graph: dict[str, Any], anomaly: dict[str, Any], replay: dict[str, Any]) -> str:
        nodes = graph.get("nodes") if isinstance(graph.get("nodes"), list) else []
        links = graph.get("links") if isinstance(graph.get("links"), list) else []
        ranked = anomaly.get("ranked_anomalies") if isinstance(anomaly.get("ranked_anomalies"), list) else []
        evidence = replay.get("evidence_stream") if isinstance(replay.get("evidence_stream"), list) else []
        flagged = [item for item in evidence if int(item.get("predicted_anomaly") or 0) == 1][:5]
        records = flagged or ranked[:5]

        lines = [
            f"Graph: {len(nodes)} nodes, {len(links)} relationships",
            f"",
            "Top anomalies to investigate:",
        ]
        if records:
            for index, item in enumerate(records, start=1):
                source = item.get("source_component") or item.get("src") or item.get("source_file") or "unknown"
                target = item.get("target_component") or item.get("dst") or "unknown"
                service = item.get("service") or item.get("protocol") or item.get("source_type") or "event"
                severity = item.get("severity", "unknown").upper()
                seq = item.get('sequence', '?')
                explanation = item.get('summary') or item.get('explanation') or ""
                exp_text = f" - {explanation}" if explanation else ""
                lines.append(
                    f"{index}. Seq #{seq} | {severity} | {source} -> {target} ({service}){exp_text}"
                )
        else:
            lines.append("1. No flagged anomalies staged yet. Run anomaly detection and export the graph.")

        if links:
            lines.append(f"")
            lines.append("Key relationships:")
            for link in links[:4]:
                rel = link.get('relation') or link.get('description') or 'related'
                lines.append(f"- {link.get('source', '?')} -> {link.get('target', '?')}: {rel}")
        return "\n".join(lines)

    @staticmethod
    def _offline_chain_status(status: dict[str, Any]) -> str:
        recovery = status.get("recovery_ledger") if isinstance(status.get("recovery_ledger"), dict) else {}
        trusted = status.get("trusted_readiness") if isinstance(status.get("trusted_readiness"), dict) else {}
        return (
            f"Chain status is {status.get('status', 'unknown')}. "
            f"Checked entries: {status.get('checked_entries', 'unknown')}. "
            f"Recovery ledger: {recovery.get('status', 'unknown')}. "
            f"Trusted evidence readiness: {trusted.get('trusted', False)}."
        )

    @staticmethod
    def _offline_anomalies(anomaly: dict[str, Any], replay: dict[str, Any]) -> str:
        ranked = anomaly.get("ranked_anomalies") if isinstance(anomaly.get("ranked_anomalies"), list) else []
        lines = [
            f"AI records: {anomaly.get('total_ai_records', 'unknown')}.",
            f"Anomalies: {anomaly.get('anomalies', 'unknown')}.",
            f"Severity counts: {anomaly.get('severity_counts', {})}.",
        ]
        if ranked:
            top = ranked[0]
            features = ", ".join(top.get("top_features") or []) or "No SHAP features stored"
            lines.append(
                f"Start with sequence {top.get('sequence', 'unknown')}, severity {top.get('severity', 'unknown')}. "
                f"Main SHAP reasons: {features}."
            )
        else:
            lines.append(f"Replay evidence records staged: {len(replay.get('evidence_stream') or [])}.")
        return "\n".join(lines)

    @staticmethod
    def _offline_compliance(
        status: dict[str, Any],
        anomaly: dict[str, Any],
        replay: dict[str, Any],
        documents: list[Any],
        page_context: dict[str, Any],
    ) -> str:
        evidence = replay.get("evidence_stream") if isinstance(replay.get("evidence_stream"), list) else []
        if not evidence:
            for key in ("ranked_anomalies", "score_trace", "records"):
                if isinstance(anomaly.get(key), list) and anomaly.get(key):
                    evidence = anomaly.get(key)
                    break
        if not evidence and isinstance(page_context.get("evidence_entries"), list):
            evidence = page_context.get("evidence_entries")
        shap_count = sum(1 for item in evidence if item.get("explanation") or item.get("summary") or item.get("top_features"))
        trusted = (status.get("trusted_readiness") or {}).get("trusted", False) if isinstance(status.get("trusted_readiness"), dict) else False
        anomaly_count = anomaly.get("anomalies", 0)
        
        doc_info = f"{len(documents)} regulation document(s) uploaded" if documents else "No regulation documents uploaded"
        
        lines = [
            "== Part-IS Compliance Readiness ==",
            f"Evidence records: {len(evidence)}",
            f"With explanations (SHAP): {shap_count}",
            f"Anomalies detected: {anomaly_count}",
            f"Chain verification: {'Trusted' if trusted else 'Not verified'}",
            f"Documentation: {doc_info}",
            f"",
            "Report Status:",
            f"- Can export evidence: {'Yes' if len(evidence) > 0 and shap_count > 0 else 'Insufficient evidence/explanations'}",
            f"- Chain integrity: {'Ready' if trusted else 'Restore verification first (IS.I.OR.200)'}",
            f"- Internal reporting: Record findings per IS.I.OR.215",
            f"- External escalation: Follow org procedure per IS.I.OR.230 if safety-critical",
        ]
        return "\n".join(lines)
