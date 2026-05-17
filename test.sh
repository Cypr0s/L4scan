#!/usr/bin/env bash

SCANNER="./L4scan"
INTERFACE="lo"

pass() { echo "$1 OK"; }
fail() { echo "$1 FAIL"; }

# 1 help -h
OUT=$("$SCANNER" -h); EC=$?
if [[ $EC -eq 0 && -n "$OUT" ]]; then
    pass "1. help -h"
else
    fail "1. help -h"
fi

# 2 help --help
OUT=$("$SCANNER" --help); EC=$?
if [[ $EC -eq 0 && -n "$OUT" ]]; then
    pass "2. help --help"
else
    fail "2. help --help"
fi

# 3 interface exit
OUT=$("$SCANNER" -i); EC=$?
if [[ $EC -eq 0 ]]; then
    pass "3. iface exit"
else
    fail "3. iface exit"
fi

# 4 tcp open
nc -l -p 13350 -k &
sleep 0.1
OUT=$("$SCANNER" -i "$INTERFACE" -t 13350 localhost)
if echo "$OUT" | grep -q "13350 tcp open"; then
    pass "4. tcp open"
else
    fail "4. tcp open"
fi
kill $(lsof -t -i:13350)
sleep 0.1

# 5 tcp closed
OUT=$("$SCANNER" -i "$INTERFACE" -t 13351 localhost)
if echo "$OUT" | grep -q "13351 tcp closed"; then
    pass "5. tcp closed"
else
    fail "5. tcp closed"
fi

# 6 udp open
nc -u -l -p 13352 >/dev/null & 
sleep 0.1
OUT=$("$SCANNER" -i "$INTERFACE" -u 13352 localhost)
if echo "$OUT" | grep -q "13352 udp open"; then
    pass "6. udp open"
else
    fail "6. udp open"
fi
kill $(lsof -t -i:13352)
sleep 0.1

# 7 udp closed
OUT=$("$SCANNER" -i "$INTERFACE" -u 13353 localhost)
if echo "$OUT" | grep -q "13353 udp closed"; then
    pass "7. udp closed"
else
    fail "7. udp closed"
fi

# 8 multiple tcp ports all open
nc -l -p 13360 -k &
nc -l -p 13361 -k &
nc -l -p 13362 -k &
sleep 0.1
OUT=$("$SCANNER" -i "$INTERFACE" -t 13360,13361,13362 localhost)
if echo "$OUT" | grep -q "13360 tcp open" && echo "$OUT" | grep -q "13361 tcp open" && echo "$OUT" | grep -q "13362 tcp open"; then
    pass "8. multiple tcp ports all open"
else
    fail "8. multiple tcp ports all open"
fi
kill $(lsof -t -i:13360)
kill $(lsof -t -i:13361)
kill $(lsof -t -i:13362)
sleep 0.1

# 9 multiple tcp ports all closed
OUT=$("$SCANNER" -i "$INTERFACE" -t 13363,13364,13365 localhost)
if echo "$OUT" | grep -q "13363 tcp closed" && echo "$OUT" | grep -q "13364 tcp closed" && echo "$OUT" | grep -q "13365 tcp closed"; then
    pass "9. multiple tcp ports all closed"
else
    fail "9. multiple tcp ports all closed"
fi

# 10 multiple tcp ports mixed open/closed
nc -l -p 13366 -k &
sleep 0.1
OUT=$("$SCANNER" -i "$INTERFACE" -t 13366,13367 localhost)
if echo "$OUT" | grep -q "13366 tcp open" && echo "$OUT" | grep -q "13367 tcp closed"; then
    pass "10. multiple tcp ports mixed open/closed"
else
    fail "10. multiple tcp ports mixed open/closed"
fi
kill $(lsof -t -i:13366)
sleep 0.1

# 11 multiple udp ports all open
nc -u -l -p 13370 >/dev/null &
nc -u -l -p 13371 >/dev/null &
nc -u -l -p 13372 >/dev/null &
sleep 0.1
OUT=$("$SCANNER" -i "$INTERFACE" -u 13370,13371,13372 localhost)
if echo "$OUT" | grep -q "13370 udp open" && echo "$OUT" | grep -q "13371 udp open" && echo "$OUT" | grep -q "13372 udp open"; then
    pass "11. multiple udp ports all open"
else
    fail "11. multiple udp ports all open"
fi
kill $(lsof -t -i:13370)
kill $(lsof -t -i:13371)
kill $(lsof -t -i:13372)
sleep 0.1

# 12 multiple udp ports all closed
OUT=$("$SCANNER" -i "$INTERFACE" -u 13373,13374,13375 localhost)
if echo "$OUT" | grep -q "13373 udp closed" && echo "$OUT" | grep -q "13374 udp closed" && echo "$OUT" | grep -q "13375 udp closed"; then
    pass "12. multiple udp ports all closed"
else
    fail "12. multiple udp ports all closed"
fi

# 13 multiple udp ports mixed open/closed
nc -u -l -p 13376 >/dev/null &
sleep 0.1
OUT=$("$SCANNER" -i "$INTERFACE" -u 13376,13377 localhost)
if echo "$OUT" | grep -q "13376 udp open" && echo "$OUT" | grep -q "13377 udp closed"; then
    pass "13. multiple udp ports mixed open/closed"
else
    fail "13. multiple udp ports mixed open/closed"
fi
kill $(lsof -t -i:13376)
sleep 0.1

# 14 tcp port range all open
nc -l -p 13380 -k &
nc -l -p 13381 -k &
nc -l -p 13382 -k &
sleep 0.1
OUT=$("$SCANNER" -i "$INTERFACE" -t 13380-13382 localhost)
if echo "$OUT" | grep -q "13380 tcp open" && echo "$OUT" | grep -q "13381 tcp open" && echo "$OUT" | grep -q "13382 tcp open"; then
    pass "14. tcp port range all open"
else
    fail "14. tcp port range all open"
fi
kill $(lsof -t -i:13380)
kill $(lsof -t -i:13381)
kill $(lsof -t -i:13382)
sleep 0.1

# 15 tcp port range all closed
OUT=$("$SCANNER" -i "$INTERFACE" -t 13383-13385 localhost)
if echo "$OUT" | grep -q "13383 tcp closed" && echo "$OUT" | grep -q "13384 tcp closed" && echo "$OUT" | grep -q "13385 tcp closed"; then
    pass "15. tcp port range all closed"
else
    fail "15. tcp port range all closed"
fi

# 16 tcp port range mixed open/closed
nc -l -p 13386 -k &
sleep 0.1
OUT=$("$SCANNER" -i "$INTERFACE" -t 13386-13388 localhost)
if echo "$OUT" | grep -q "13386 tcp open" && echo "$OUT" | grep -q "13387 tcp closed" && echo "$OUT" | grep -q "13388 tcp closed"; then
    pass "16. tcp port range mixed open/closed"
else
    fail "16. tcp port range mixed open/closed"
fi
kill $(lsof -t -i:13386)
sleep 0.1

# 17 udp port range all open
nc -u -l -p 13390 >/dev/null &
nc -u -l -p 13391 >/dev/null &
nc -u -l -p 13392 >/dev/null &
sleep 0.1
OUT=$("$SCANNER" -i "$INTERFACE" -u 13390-13392 localhost)
if echo "$OUT" | grep -q "13390 udp open" && echo "$OUT" | grep -q "13391 udp open" && echo "$OUT" | grep -q "13392 udp open"; then
    pass "17. udp port range all open"
else
    fail "17. udp port range all open"
fi
kill $(lsof -t -i:13390)
kill $(lsof -t -i:13391)
kill $(lsof -t -i:13392)
sleep 0.1

# 18 udp port range all closed
OUT=$("$SCANNER" -i "$INTERFACE" -u 13393-13395 localhost)
if echo "$OUT" | grep -q "13393 udp closed" && echo "$OUT" | grep -q "13394 udp closed" && echo "$OUT" | grep -q "13395 udp closed"; then
    pass "18. udp port range all closed"
else
    fail "18. udp port range all closed"
fi

# 19 udp port range mixed open/closed
nc -u -l -p 13396 >/dev/null &
sleep 0.1
OUT=$("$SCANNER" -i "$INTERFACE" -u 13396-13398 localhost)
if echo "$OUT" | grep -q "13396 udp open" && echo "$OUT" | grep -q "13397 udp closed" && echo "$OUT" | grep -q "13398 udp closed"; then
    pass "19. udp port range mixed open/closed"
else
    fail "19. udp port range mixed open/closed"
fi
kill $(lsof -t -i:13396)
sleep 0.1

# 20 tcp and udp same port both open
nc -l -p 13400 -k &
nc -u -l -p 13400 >/dev/null &
sleep 0.1
OUT=$("$SCANNER" -i "$INTERFACE" -t 13400 -u 13400 localhost)
if echo "$OUT" | grep -q "13400 tcp open" && echo "$OUT" | grep -q "13400 udp open"; then
    pass "20. tcp and udp same port both open"
else
    fail "20. tcp and udp same port both open"
fi
kill $(lsof -t -i:13400)
sleep 0.1

# 21 tcp and udp different ports both open
nc -l -p 13401 -k &
nc -u -l -p 13402 >/dev/null &
sleep 0.1
OUT=$("$SCANNER" -i "$INTERFACE" -t 13401 -u 13402 localhost)
if echo "$OUT" | grep -q "13401 tcp open" && echo "$OUT" | grep -q "13402 udp open"; then
    pass "21. tcp and udp different ports both open"
else
    fail "21. tcp and udp different ports both open"
fi
kill $(lsof -t -i:13401)
kill $(lsof -t -i:13402)
sleep 0.1

# 22 tcp and udp different ports both closed
OUT=$("$SCANNER" -i "$INTERFACE" -t 13403 -u 13404 localhost)
if echo "$OUT" | grep -q "13403 tcp closed" && echo "$OUT" | grep -q "13404 udp closed"; then
    pass "22. tcp and udp different ports both closed"
else
    fail "22. tcp and udp different ports both closed"
fi

# 23 tcp open udp closed
nc -l -p 13405 -k  &
sleep 0.1
OUT=$("$SCANNER" -i "$INTERFACE" -t 13405 -u 13406 localhost)
if echo "$OUT" | grep -q "13405 tcp open" && echo "$OUT" | grep -q "13406 udp closed"; then
    pass "23. tcp open udp closed"
else
    fail "23. tcp open udp closed"
fi
kill $(lsof -t -i:13405)
sleep 0.1

# 24 tcp closed udp open
nc -u -l -p 13408 >/dev/null &
sleep 0.1
OUT=$("$SCANNER" -i "$INTERFACE" -t 13407 -u 13408 localhost)
if echo "$OUT" | grep -q "13407 tcp closed" && echo "$OUT" | grep -q "13408 udp open"; then
    pass "24. tcp closed udp open"
else
    fail "24. tcp closed udp open"
fi
kill $(lsof -t -i:13408)
sleep 0.1

# 25 tcp range and udp range mixed
nc -l -p 13410 -k &
nc -u -l -p 13413 >/dev/null &
sleep 0.1
OUT=$("$SCANNER" -i "$INTERFACE" -t 13410-13411 -u 13412-13413 localhost)
if echo "$OUT" | grep -q "13410 tcp open" && echo "$OUT" | grep -q "13411 tcp closed" && echo "$OUT" | grep -q "13412 udp closed" && echo "$OUT" | grep -q "13413 udp open"; then
    pass "25. tcp range and udp range mixed"
else
    fail "25. tcp range and udp range mixed"
fi
kill $(lsof -t -i:13410)
kill $(lsof -t -i:13413)
sleep 0.1


# 26 tcp edge case ports
nc -l -p 1 -k &
nc -l -p 65535 -k &
sleep 0.1
OUT=$("$SCANNER" -i "$INTERFACE" -t 1,65535 localhost)
if echo "$OUT" | grep -q "1 tcp open" && echo "$OUT" | grep -q "65535 tcp open"; then
    pass "26. tcp edge case ports"
else
    fail "26. tcp edge case ports"
fi
kill $(lsof -t -i:1)
kill $(lsof -t -i:65535)
sleep 0.1


# 27 ipv6 tcp open
nc -6 -l -p 13420 -k &
sleep 0.1
OUT=$("$SCANNER" -i "$INTERFACE" -t 13420 ::1)
if echo "$OUT" | grep -q "13420 tcp open"; then
    pass "27. ipv6 tcp open"
else
    fail "27. ipv6 tcp open"
fi
kill $(lsof -t -iTCP:13420)
sleep 0.1

# 28 ipv6 tcp closed
OUT=$("$SCANNER" -i "$INTERFACE" -t 13421 ::1)
if echo "$OUT" | grep -q "13421 tcp closed"; then
    pass "28. ipv6 tcp closed"
else
    fail "28. ipv6 tcp closed"
fi

# 29 ipv6 udp open
nc -6 -u -l -p 13422 >/dev/null &
sleep 0.1
OUT=$("$SCANNER" -i "$INTERFACE" -u 13422 ::1)
if echo "$OUT" | grep -q "13422 udp open"; then
    pass "29. ipv6 udp open"
else
    fail "29. ipv6 udp open"
fi
kill $(lsof -t -iUDP:13422)
sleep 0.1

# 30 ipv6 udp closed
OUT=$("$SCANNER" -i "$INTERFACE" -u 13423 ::1)
if echo "$OUT" | grep -q "13423 udp closed"; then
    pass "30. ipv6 udp closed"
else
    fail "30. ipv6 udp closed"
fi

# 31 ipv6 tcp multiple ports mixed
nc -6 -l -p 13424 -k &
sleep 0.1
OUT=$("$SCANNER" -i "$INTERFACE" -t 13424,13425 ::1)
if echo "$OUT" | grep -q "13424 tcp open" && echo "$OUT" | grep -q "13425 tcp closed"; then
    pass "31. ipv6 tcp multiple ports mixed"
else
    fail "31. ipv6 tcp multiple ports mixed"
fi
kill $(lsof -t -iTCP:13424)
sleep 0.1

# 32 ipv6 udp multiple ports mixed
nc -6 -u -l -p 13426 >/dev/null &
sleep 0.1
OUT=$("$SCANNER" -i "$INTERFACE" -u 13426,13427 ::1)
if echo "$OUT" | grep -q "13426 udp open" && echo "$OUT" | grep -q "13427 udp closed"; then
    pass "32. ipv6 udp multiple ports mixed"
else
    fail "32. ipv6 udp multiple ports mixed"
fi
kill $(lsof -t -iUDP:13426)
sleep 0.1