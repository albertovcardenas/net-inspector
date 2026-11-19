
import sqlite3


def crear_base_datos(ruta_db="net_inspector.db"):

    with sqlite3.connect(ruta_db) as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS conexiones (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    fecha_hora TEXT NOT NULL
        CHECK (LENGTH(TRIM(fecha_hora)) > 0),

    ip_origen TEXT NOT NULL
        CHECK (LENGTH(TRIM(ip_origen)) > 0),

    ip_destino TEXT NOT NULL
        CHECK (LENGTH(TRIM(ip_destino)) > 0),

    puerto_destino TEXT,

    protocolo TEXT NOT NULL
        CHECK (LENGTH(TRIM(protocolo)) > 0),

    bytes_transmitidos INTEGER NOT NULL
        CHECK (
            typeof(bytes_transmitidos) = 'integer'
            AND bytes_transmitidos >= 0
        )
)
        """)


def guardar_conexiones(conexiones, ruta_db="net_inspector.db"):

    with sqlite3.connect(ruta_db) as db:
        db.executemany("""
            INSERT INTO conexiones (
                fecha_hora,
                ip_origen,
                ip_destino,
                puerto_destino,
                protocolo,
                bytes_transmitidos
            )
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            (
                conexion.fecha_hora,
                conexion.ip_origen,
                conexion.ip_destino,
                conexion.puerto_destino,
                conexion.protocolo,
                conexion.bytes_transmitidos
            )
            for conexion in conexiones
        ))


def consultar_resumen(ruta_db="net_inspector.db"):

    with sqlite3.connect(ruta_db) as db:
        resultado = db.execute("""
            SELECT COUNT(*), SUM(bytes_transmitidos)
            FROM conexiones
        """).fetchone()

    return resultado
def consultar_top_tcp(ruta_db="net_inspector.db", limite=5):

    with sqlite3.connect(ruta_db) as db:

        resultados = db.execute("""
            SELECT
                ip_origen,
                COUNT(*) AS conexiones,
                SUM(bytes_transmitidos) AS total_bytes,
                AVG(bytes_transmitidos) AS promedio_bytes
            FROM conexiones
            WHERE LOWER(protocolo) = 'tcp'
            GROUP BY ip_origen
            ORDER BY conexiones DESC
            LIMIT ?
        """, (limite,)).fetchall()

    return resultados    
