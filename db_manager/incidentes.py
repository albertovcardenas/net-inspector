
import sqlite3


def guardar_alertas(alertas, umbral, ventana_segundos,
                    ruta_db="net_inspector.db"):

    with sqlite3.connect(ruta_db) as db:

        db.execute("""
            CREATE TABLE IF NOT EXISTS incidentes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tipo TEXT NOT NULL,
                ip_origen TEXT NOT NULL,
                cantidad INTEGER NOT NULL,
                inicio TEXT NOT NULL,
                fin TEXT NOT NULL,
                umbral INTEGER NOT NULL,
                ventana_segundos INTEGER NOT NULL,
                UNIQUE(tipo, ip_origen, inicio, fin,
                       umbral, ventana_segundos)
            )
        """)

        db.executemany("""
            INSERT OR IGNORE INTO incidentes (
                tipo, ip_origen, cantidad, inicio, fin,
                umbral, ventana_segundos
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            (
                alerta["tipo"],
                alerta["ip_origen"],
                alerta["cantidad"],
                alerta["inicio"],
                alerta["fin"],
                umbral,
                ventana_segundos
            )
            for alerta in alertas
        ))
