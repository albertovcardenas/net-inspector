
import sqlite3
from pathlib import Path
import matplotlib.pyplot as plt


def graficar_protocolos(ruta_db):

    # Consultar los protocolos almacenados
    with sqlite3.connect(ruta_db) as db:

        datos = db.execute("""
            SELECT protocolo, COUNT(*)
            FROM conexiones
            GROUP BY protocolo
            ORDER BY COUNT(*) DESC
        """).fetchall()

    if not datos:
        print("No existen conexiones para graficar.")
        return None

    # Separar protocolos y cantidades
    protocolos, cantidades = zip(*datos)

    # Generar gráfica
    fig, ax = plt.subplots(figsize=(8, 5))

    ax.bar(protocolos, cantidades)

    ax.set_title("Net Inspector - Distribución de protocolos")
    ax.set_xlabel("Protocolo")
    ax.set_ylabel("Cantidad de conexiones")

    fig.tight_layout()

    # Guardar imagen
    ruta_salida = Path("visualizer/protocolos_integracion.png")

    fig.savefig(ruta_salida, dpi=150)
    plt.close(fig)

    return ruta_salida


def graficar_puertos_destino(ruta_db):

    # Consultar los 10 puertos más frecuentes
    with sqlite3.connect(ruta_db) as db:

        datos = db.execute("""
            SELECT puerto_destino, COUNT(*) AS total
            FROM conexiones
            WHERE puerto_destino IS NOT NULL
            AND TRIM(CAST(puerto_destino AS TEXT)) != ''
            GROUP BY puerto_destino
            ORDER BY total DESC
            LIMIT 10
        """).fetchall()

    if not datos:
        print("No existen puertos para graficar.")
        return None

    # Separar puertos y cantidades
    puertos, cantidades = zip(*datos)

    # Crear gráfica
    fig, ax = plt.subplots(figsize=(10, 5))

    ax.bar([str(p) for p in puertos], cantidades)

    ax.set_title("Net Inspector - Puertos de destino")
    ax.set_xlabel("Puerto de destino")
    ax.set_ylabel("Cantidad de conexiones")

    plt.xticks(rotation=45)

    fig.tight_layout()

    # Guardar imagen
    ruta_salida = (
        Path(__file__).resolve().parent
        / "puertos_destino_integracion.png"
    )

    fig.savefig(ruta_salida, dpi=150)
    plt.close(fig)

    return ruta_salida


def graficar_trafico_por_minuto(ruta_db):

    from datetime import datetime
    from collections import defaultdict

    # Consultar fechas y bytes almacenados
    with sqlite3.connect(ruta_db) as db:

        datos = db.execute("""
            SELECT fecha_hora, bytes_transmitidos
            FROM conexiones
            WHERE fecha_hora IS NOT NULL
            AND bytes_transmitidos IS NOT NULL
        """).fetchall()

    if not datos:
        print("No existen registros para graficar.")
        return None

    # Agrupar bytes por minuto
    trafico = defaultdict(int)

    for fecha_texto, cantidad_bytes in datos:

        fecha = datetime.strptime(
            fecha_texto,
            "%Y/%m/%d %H:%M:%S.%f"
        )

        minuto = fecha.replace(
            second=0,
            microsecond=0
        )

        trafico[minuto] += int(cantidad_bytes)

    # Ordenar los minutos cronológicamente
    minutos = sorted(trafico.keys())

    # Convertir bytes a MiB
    cantidades = [
        trafico[minuto] / (1024 ** 2)
        for minuto in minutos
    ]

    # Crear gráfica
    fig, ax = plt.subplots(figsize=(11, 5))

    ax.plot(
        minutos,
        cantidades,
        marker="o"
    )

    ax.set_title("Net Inspector - Tráfico por minuto")
    ax.set_xlabel("Fecha y hora")
    ax.set_ylabel("Tráfico (MiB por minuto)")

    ax.grid(True, alpha=0.3)
    ax.set_ylim(bottom=0)

    fig.autofmt_xdate()
    fig.tight_layout()

    # Guardar gráfica
    ruta_salida = (
        Path(__file__).resolve().parent
        / "trafico_por_minuto_integracion.png"
    )

    fig.savefig(ruta_salida, dpi=150)
    plt.close(fig)

    print("Minutos representados:", len(minutos))

    return ruta_salida
