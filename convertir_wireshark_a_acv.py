"""Convierte CSV de conversaciones Wireshark (interfaz en español) a ACV NetLab.

Uso:
    python convertir_wireshark_a_acv.py conversaciones_tcp.csv conversaciones_udp.csv --ip-local 192.168.1.50 --salida trafico_real_acv_netlab.csv

Precisión: una fila por conversación observada. Los bytes son bidireccionales
agregados de la conversación, y src_ip representa la computadora de referencia;
no se deduce quién inició TCP/UDP a partir de Dirección A/B. No transforma
paquetes individuales en flujos CTU-13 ni reconstruye todas las sesiones.
"""

import argparse
import csv
import ipaddress
from datetime import datetime
from pathlib import Path

CAMPOS_SALIDA = ["timestamp", "src_ip", "dst_ip", "dst_port", "protocol", "bytes"]
CAMPOS_REQUERIDOS = {
    "Dirección A", "Puerto A", "Dirección B", "Puerto B", "Bytes", "Inicio abs"
}


def convertir(archivos, ip_local, salida):
    ipaddress.ip_address(ip_local)
    registros = []
    resumen = {}

    for protocolo, ruta in archivos.items():
        total = 0
        excluidos = 0
        with Path(ruta).open("r", encoding="utf-8-sig", newline="") as f:
            lector = csv.DictReader(f)
            columnas = set(lector.fieldnames or [])
            faltantes = CAMPOS_REQUERIDOS - columnas
            if faltantes:
                raise ValueError(f"{ruta}: faltan columnas {sorted(faltantes)}")
            for numero, fila in enumerate(lector, start=2):
                if None in fila or any(v is None for v in fila.values()):
                    raise ValueError(f"{ruta}, fila {numero}: columnas irregulares")
                a, b = fila["Dirección A"].strip(), fila["Dirección B"].strip()
                ipaddress.ip_address(a)
                ipaddress.ip_address(b)
                if ip_local not in (a, b):
                    excluidos += 1
                    continue
                # No inferimos qué extremo inició la comunicación: fijamos
                # nuestro equipo como origen de referencia para el análisis.
                otro = b if a == ip_local else a
                puerto_remoto = fila["Puerto B"] if a == ip_local else fila["Puerto A"]
                puerto = int(puerto_remoto)
                if not 0 <= puerto <= 65535:
                    raise ValueError(f"{ruta}, fila {numero}: puerto inválido")
                numero_bytes = int(fila["Bytes"])
                if numero_bytes < 0:
                    raise ValueError(f"{ruta}, fila {numero}: bytes negativos")
                instante = datetime.fromisoformat(fila["Inicio abs"].strip())
                registros.append({
                    "timestamp": instante.strftime("%Y/%m/%d %H:%M:%S.%f"),
                    "src_ip": ip_local,
                    "dst_ip": otro,
                    "dst_port": str(puerto),
                    "protocol": protocolo.upper(),
                    "bytes": str(numero_bytes),
                })
                total += 1
        resumen[protocolo.upper()] = (total, excluidos)

    registros.sort(key=lambda r: r["timestamp"])
    with Path(salida).open("w", encoding="utf-8", newline="") as f:
        escritor = csv.DictWriter(f, fieldnames=CAMPOS_SALIDA)
        escritor.writeheader()
        escritor.writerows(registros)

    print(f"Archivo creado: {salida}")
    for proto, (inc, exc) in resumen.items():
        print(f"{proto}: {inc} conversaciones incluidas; {exc} excluidas")
    print(f"Total conversaciones: {len(registros)}")
    print(f"Bytes observados (ambos sentidos): {sum(int(r['bytes']) for r in registros):,}")
    return registros


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tcp", help="CSV conversaciones TCP exportado de Wireshark")
    parser.add_argument("udp", help="CSV conversaciones UDP exportado de Wireshark")
    parser.add_argument("--ip-local", default="192.168.1.50", help="Dirección IP de la computadora capturadora")
    parser.add_argument("--salida", default="trafico_real_acv_netlab.csv")
    args = parser.parse_args()
    convertir({"tcp": args.tcp, "udp": args.udp}, args.ip_local, args.salida)
