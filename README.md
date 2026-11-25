# AI Phishing & Log Analyzer

Prototipo en Python para analizar registros de alertas y correos sospechosos combinando indicadores básicos de red/seguridad (URLs con IP, TLDs sospechosos, acortadores y lenguaje de urgencia) con evaluación asistida por IA (Gemini API), incluyendo un modo heurístico local de respaldo.

## Características
- Lectura por lotes de archivos de eventos/alertas desde CLI.
- Detección de señales comunes de phishing e ingeniería social.
- Integración con la API de Gemini (`gemini-2.5-flash`) con respaldo local automático si no hay `GEMINI_API_KEY`.
- Salida legible en consola o estructurada en JSON.

## Uso rápido

```bash
pip install google-genai
python analyzer.py --file sample_alerts.txt
```

Para activar el análisis con Gemini:

```bash
export GEMINI_API_KEY="tu_api_key"
python analyzer.py --file sample_alerts.txt
```
