
from itertools import islice, chain
from datetime import datetime
from pathlib import Path
from visualizer.estadisticas_pandas import resumen_protocolos_pandas

from log_engine.lector_ctu13 import leer_ctu13
from log_engine.normalizador import convertir_ctu13, convertir_generico

from security_core.detector_anomalias import DetectorAnomalias

from security_core.host import Host

from db_manager.database import (
    crear_base_datos,
    guardar_conexiones,
    consultar_resumen
)

from db_manager.incidentes import guardar_alertas
from visualizer.resumen import (graficar_protocolos, graficar_puertos_destino, graficar_trafico_por_minuto)


def _ejecutar_analisis(
    archivo="ctu13_escenario7.binetflow",
    limite=None,
    umbral=100,
    ventana=60
):

    print("================================")
    print("       NET INSPECTOR")
    print("================================")

    # Configuración de la prueba

    # Crear una base independiente para esta prueba
    identificador = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    ruta_db = f"net_inspector_integracion_{identificador}.db"

    # Verificar que exista el archivo de entrada
    if not Path(archivo).exists():
        print("Error: no se encontró el archivo de tráfico.")
        return

    # Leer registros e identificar su formato
    registros = leer_ctu13(archivo)

    primer_registro = next(registros, None)

    if primer_registro is None:
        print("Error: el archivo no contiene registros.")
        return None

    campos = set(primer_registro.keys())

    campos_ctu13 = {
        "StartTime", "SrcAddr", "DstAddr",
        "Dport", "Proto", "TotBytes"
    }

    campos_genericos = {
        "timestamp", "src_ip", "dst_ip",
        "dst_port", "protocol", "bytes"
    }

    if campos_ctu13.issubset(campos):
        normalizar = convertir_ctu13
        formato = "CTU-13"

    elif campos_genericos.issubset(campos):
        normalizar = convertir_generico
        formato = "CSV genérico"

    else:
        print("Error: formato de archivo no reconocido.")
        print("Columnas encontradas:", sorted(campos))
        return None

    print("Formato detectado:", formato)

    # Recuperar el primer registro para no perderlo
    registros = chain((primer_registro,), registros)

    conexiones = []
    rechazados = 0

    for numero, registro in enumerate(islice(registros, limite), start=1):

        try:
            conexion = normalizar(registro)

        except (ValueError, KeyError, TypeError) as error:
            rechazados += 1

            if rechazados <= 3:
                print(f"Registro {numero} rechazado: {error}")

            continue

        conexiones.append(conexion)

    print("Conexiones procesadas:", len(conexiones))

    print("Registros rechazados:", rechazados)
    
    if not conexiones:
        print("\nAnálisis detenido: no se encontraron conexiones válidas.")
        return None


    # Analizar actividad por host
    hosts = {}

    for conexion in conexiones:
        ip = conexion.ip_origen

        if ip not in hosts:
            hosts[ip] = Host(ip)

        hosts[ip].registrar_conexion(conexion)

    # Identificar los cinco hosts con más conexiones
    ordenados = sorted(
        hosts.values(),
        key=lambda host: host.total_conexiones,
        reverse=True
    )

    print("\n=== CINCO HOSTS CON MÁS CONEXIONES ===")

    for host in ordenados[:5]:
        print(
            "IP:", host.ip,
            "| Conexiones:", host.total_conexiones,
            "| Bytes:", host.total_bytes
        )

    # Analizar posibles anomalías
    detector = DetectorAnomalias(
        umbral_flujos=umbral,
        ventana_segundos=ventana
    )

    alertas = list(detector.detectar_rafagas(conexiones))

    print("Alertas detectadas:", len(alertas))

    # Crear base de datos
    crear_base_datos(ruta_db)

    # Guardar conexiones
    guardar_conexiones(conexiones, ruta_db)

    # Análisis estadístico con Pandas
    resumen_pandas = resumen_protocolos_pandas(ruta_db)

    print("\n=== ESTADÍSTICAS CON PANDAS ===")
    print(resumen_pandas.to_string(index=False))

    # Guardar alertas
    guardar_alertas(alertas, umbral, ventana, ruta_db)

    # Consultar resultados
    cantidad, total_bytes = consultar_resumen(ruta_db)

    print("--------------------------------")
    print("Conexiones almacenadas:", cantidad)
    print("Bytes registrados:", total_bytes)
    print("Base de datos:", ruta_db)
    print("--------------------------------")
    ruta_grafica = graficar_protocolos(ruta_db)
    if ruta_grafica is not None:
        print("Gráfica guardada en:", ruta_grafica)


    # Generar gráfica de puertos de destino
    ruta_grafica_puertos = graficar_puertos_destino(ruta_db)

    if ruta_grafica_puertos is not None:
        print("Gráfica de puertos:", ruta_grafica_puertos)


    # Generar gráfica temporal
    ruta_grafica_trafico = graficar_trafico_por_minuto(ruta_db)

    if ruta_grafica_trafico is not None:
        print("Gráfica temporal:", ruta_grafica_trafico)

    print("Análisis finalizado correctamente")

    return {
        "base_datos": ruta_db,
        "conexiones": cantidad,
        "bytes": total_bytes,
        "alertas": len(alertas),
        "graficas": {
            "Protocolos": str(ruta_grafica) if ruta_grafica else None,
            "Puertos": str(ruta_grafica_puertos) if ruta_grafica_puertos else None,
            "Tráfico temporal": str(ruta_grafica_trafico) if ruta_grafica_trafico else None
        }
    }





def main(
    archivo="ctu13_escenario7.binetflow",
    limite=None,
    umbral=100,
    ventana=60
):
    try:
        return _ejecutar_analisis(
            archivo=archivo,
            limite=limite,
            umbral=umbral,
            ventana=ventana
        )

    except UnicodeDecodeError as error:
        print("Error: el archivo contiene datos incompatibles con UTF-8.")
        print("Archivo:", archivo)
        print("Detalle:", error)
        return None


if __name__ == "__main__":
    main()
