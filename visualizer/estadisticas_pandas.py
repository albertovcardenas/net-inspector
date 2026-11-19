
import sqlite3
import pandas as pd


def resumen_protocolos_pandas(ruta_db):

    # Leer las conexiones almacenadas
    with sqlite3.connect(ruta_db) as db:
        datos = pd.read_sql_query(
            """
            SELECT protocolo, bytes_transmitidos
            FROM conexiones
            """,
            db
        )

    # Agrupar y calcular estadísticas
    resumen = datos.groupby(
        "protocolo",
        as_index=False
    ).agg(
        conexiones=("bytes_transmitidos", "count"),
        total_bytes=("bytes_transmitidos", "sum"),
        promedio_bytes=("bytes_transmitidos", "mean")
    )

    # Ordenar de mayor a menor cantidad de conexiones
    resumen = resumen.sort_values(
        "conexiones",
        ascending=False
    )

    return resumen
