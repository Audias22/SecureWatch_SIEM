@echo off
chcp 65001 >nul
title SecureWatch - Terminal del colector (solo lectura)
echo  Mostrando la terminal del colector en vivo. Cerrar esta ventana NO detiene el colector.
echo.
powershell -NoProfile -Command "Get-Content -Path '%~dp0..\storage\collector.log' -Encoding UTF8 -Tail 40 -Wait"
