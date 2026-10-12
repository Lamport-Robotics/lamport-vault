#!/bin/bash
set -u
H=$1; cd "$H/vec" || exit 1
rm -f *.pub *.prv *.aux *.sig *.bin
: > m_empty.bin; printf 'a' > m_1.bin
printf 'The powers not delegated to the United States by the Constitution, nor prohibited by it to the States, are reserved to the States respectively, or to the people.\n' > m_rfc.bin
head -c 55 /dev/urandom > m_55.bin; head -c 64 /dev/urandom > m_64.bin; head -c 1000 /dev/urandom > m_1000.bin; head -c 4096 /dev/urandom > m_4096.bin
gen() {
  local name=$1 parm=$2; shift 2
  "$H/src/demo" genkey "$name" "$parm" >/dev/null 2>&1 || { echo "genkey $name failed"; return 1; }
  for step in "$@"; do
    local adv=${step%%:*} files=${step#*:}
    if [ "$adv" != "0" ]; then "$H/src/demo" advance "$name" "$adv" >/dev/null 2>&1 || echo "advance failed $name"; fi
    for f in $files; do
      cp "$f" "$name.$f"
      "$H/src/demo" sign "$name" "$name.$f" >/dev/null 2>&1 || echo "sign failed $name $f"
      "$H/src/demo" verify "$name" "$name.$f" | grep -q "verified" || echo "hash-sigs self-verify FAILED $name $f"
    done
  done
}
t0=$(date +%s)
gen w4h5  5/4  "0:m_empty.bin m_1.bin m_rfc.bin" "26:m_55.bin m_1000.bin m_4096.bin"
gen w4h10 10/4 "0:m_rfc.bin m_64.bin" "1020:m_1.bin m_4096.bin"
gen w4h15 15/4 "0:m_rfc.bin" "32766:m_1000.bin"
gen w1h5  5/1  "0:m_rfc.bin m_empty.bin" "29:m_64.bin"
gen w2h5  5/2  "0:m_rfc.bin m_1.bin" "29:m_1000.bin"
gen w8h5  5/8  "0:m_rfc.bin m_empty.bin" "29:m_4096.bin"
gen w8h10 10/8 "0:m_rfc.bin" "1022:m_55.bin"
echo "done in $(( $(date +%s) - t0 ))s"
ls *.sig | wc -l
for s in *.sig; do echo "$s $(wc -c < "$s") q=$(xxd -s 4 -l 4 -p "$s")"; done
