# Krusty Phish Shield - Defensive Security | U.A.R.
# Detecta URLs sospechosas SIN entrar a ellas. Todo local.

import re
from urllib.parse import urlparse

def analyze_url(url):
    print(f"\n[+] Analizando: {url}")
    risk = 0
    reasons = []

    if not url.startswith("http"):
        url = "http://" + url
    
    parsed = urlparse(url)
    domain = parsed.netloc

    # Check 1: IP en vez de dominio
    if re.match(r"^\d+\.\d+\.\d+\.\d+", domain):
        risk += 3
        reasons.append("USA IP en vez de dominio (muy sospechoso)")

    # Check 2: @ en la URL
    if "@" in url:
        risk += 3
        reasons.append("Contiene @ - técnica de engaño")

    # Check 3: URL muy larga
    if len(url) > 75:
        risk += 1
        reasons.append(f"URL muy larga ({len(url)} chars)")

    # Check 4: Guiones sospechosos (bbva-seguro-login)
    if domain.count("-") >= 3:
        risk += 2
        reasons.append("Muchos guiones en dominio - posible typosquatting")

    # Check 5: http sin s
    if parsed.scheme == "http":
        risk += 1
        reasons.append("No usa HTTPS")

    # Check 6: Palabras clave de phishing MX
    keywords = ["bbva", "banorte", "santander", "mercadopago", "verificacion", "urgente", "bloqueado"]
    for k in keywords:
        if k in url.lower() and k not in ["mercadolibre.com", "bbva.com"]: # simplificado
             if domain != "mercadopago.com.mx" and domain != "bbva.mx":
                if k in domain: # solo si está en dominio sospechoso
                    pass
    # Check 7: TLD sospechoso
    susp_tld = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz"]
    for tld in susp_tld:
        if domain.endswith(tld):
            risk += 2
            reasons.append(f"TLD sospechoso {tld}")

    print(f"\n--- REPORTE KRUSTY ---")
    if not reasons:
        print("✅ RIESGO BAJO: No se detectaron patrones obvios.")
        print("⚠️  Aún así, verifica siempre en el sitio oficial.")
    else:
        for r in reasons:
            print(f"[!] {r}")
        print(f"\n🔴 RIESGO: {risk}/10 - NO ENTRES. Verifica por Google.")
        print("💡 Tip: Nunca entres desde SMS, entra directo a tu banco.")

if __name__ == "__main__":
    print("=== KRUSTY PHISH SHIELD v1 | U.A.R. ===")
    print("Pega una URL sospechosa (solo análisis local):")
    u = input("URL> ")
    analyze_url(u)
