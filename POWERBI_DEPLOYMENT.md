# NEXUS DANIP Power BI API

`https://mdl-ni-ai.streamlit.app/` is the Streamlit UI. It cannot expose the app's custom port 8502 as `/api/powerbi/*`. Deploy `powerbi_api.py` separately as an HTTPS service.

Streamlit Secrets:
```toml
POWERBI_API_BASE_URL = "https://YOUR-PUBLIC-API-DOMAIN"
POWERBI_API_KEY = "YOUR-SAME-POWERBI-API-KEY"
```

Do not set `POWERBI_API_BASE_URL` to `https://mdl-ni-ai.streamlit.app`.

Power BI query:
```powerquery
let
    Source = Json.Document(Web.Contents("https://YOUR-PUBLIC-API-DOMAIN/api/powerbi/wide", [Headers=[#"x-api-key"="YOUR-POWERBI-API-KEY"]])),
    Data = Table.FromRecords(Source[data])
in
    Data
```

Start API: `uvicorn powerbi_api:app --host 0.0.0.0 --port $PORT`
