import argparse
import json
import os
import re
from pathlib import Path

try:
    from google import genai
except ImportError:
    genai = None


SUSPICIOUS_TLDS = (".xyz", ".top", ".click", ".zip", ".tk")
URGENCY_WORDS = ("urgente", "bloqueada", "verifique", "inusual", "adjunto.exe", "suspendida")
IP_URL_PATTERN = re.compile(r"https?://\d{1,3}(?:\.\d{1,3}){3}")


def heuristic_analysis(line: str) -> dict:
    """Análisis local de respaldo cuando no hay clave de API configurada."""
    lower = line.lower()
    score = 0
    reasons = []

    if IP_URL_PATTERN.search(lower):
        score += 40
        reasons.append("Contiene URL apuntando directamente a una dirección IP.")

    if any(tld in lower for tld in SUSPICIOUS_TLDS):
        score += 25
        reasons.append("Utiliza un dominio de nivel superior (TLD) frecuente en campañas maliciosas.")

    if "bit.ly" in lower or "tinyurl" in lower:
        score += 15
        reasons.append("Emplea un acortador de URL que oculta el destino real.")

    matched_words = [w for w in URGENCY_WORDS if w in lower]
    if matched_words:
        score += 25
        reasons.append(f"Usa lenguaje de urgencia o ingeniería social ({', '.join(matched_words)}).")

    if score >= 60:
        risk = "ALTO"
    elif score >= 30:
        risk = "MEDIO"
    else:
        risk = "BAJO"

    if not reasons:
        reasons.append("No se encontraron indicadores evidentes de phishing en las reglas básicas.")

    return {
        "risk_level": risk,
        "confidence": min(95, 55 + score // 2),
        "reasons": reasons,
        "recommended_action": "Bloquear remitente/URL y revisar logs de red" if risk == "ALTO" else "Monitorear y validar con el usuario",
    }


def analyze_with_gemini(line: str, api_key: str) -> dict:
    """Evalúa el evento usando la API de Gemini."""
    client = genai.Client(api_key=api_key)
    prompt = (
        "Eres un analista Junior de ciberseguridad. Analiza este registro de alerta/correo "
        "y responde ÚNICAMENTE con un JSON válido con las claves: "
        "'risk_level' ('BAJO', 'MEDIO' o 'ALTO'), "
        "'confidence' (entero de 0 a 100), "
        "'reasons' (lista de 1 a 3 frases cortas en español), "
        "'recommended_action' (frase corta en español).\n\n"
        f"Registro: {line}"
    )
    response = client.models.generate_content(
        model="gemini-2.5-flash",
        contents=prompt,
    )
    raw_text = (response.text or "").strip()
    cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", raw_text, flags=re.MULTILINE).strip()
    return json.loads(cleaned)


def analyze_file(file_path: Path) -> list[dict]:
    """Procesa cada línea no vacía del archivo de registros."""
    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    results = []

    for index, raw_line in enumerate(file_path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        if api_key and genai is not None:
            try:
                assessment = analyze_with_gemini(line, api_key)
                assessment["engine"] = "gemini-2.5-flash"
            except Exception as exc:
                assessment = heuristic_analysis(line)
                assessment["engine"] = f"heuristic-fallback ({type(exc).__name__})"
        else:
            assessment = heuristic_analysis(line)
            assessment["engine"] = "heuristic-local"

        results.append({
            "line_number": index,
            "raw_event": line,
            **assessment,
        })

    return results


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Analizador básico de alertas y correos sospechosos apoyado en IA."
    )
    parser.add_argument(
        "--file",
        default="sample_alerts.txt",
        help="Ruta al archivo de logs o alertas (por defecto: sample_alerts.txt)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Imprime la salida en formato JSON",
    )
    args = parser.parse_args()

    target = Path(args.file)
    if not target.exists():
        raise FileNotFoundError(f"No se encontró el archivo: {target}")

    report = analyze_file(target)

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return

    print("=== REPORTE DE ANÁLISIS DE ALERTAS ===\n")
    for item in report:
        print(f"[Evento #{item['line_number']}] Riesgo: {item['risk_level']} | Confianza: {item['confidence']}% | Motor: {item['engine']}")
        print(f"  Evento: {item['raw_event']}")
        for reason in item["reasons"]:
            print(f"  - Motivo: {reason}")
        print(f"  Acción sugerida: {item['recommended_action']}\n")


if __name__ == "__main__":
    main()