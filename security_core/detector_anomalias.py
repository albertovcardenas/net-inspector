
from collections import defaultdict, deque
from datetime import datetime, timedelta


class DetectorAnomalias:

    def __init__(self, umbral_flujos=100, ventana_segundos=60):

        if umbral_flujos < 1:
            raise ValueError("El umbral debe ser mayor que cero")

        if ventana_segundos <= 0:
            raise ValueError("La ventana debe ser mayor que cero")

        self.umbral_flujos = umbral_flujos
        self.ventana = timedelta(seconds=ventana_segundos)

    def detectar_rafagas(self, conexiones):

        # Organizar conexiones cronológicamente
        conexiones_ordenadas = sorted(
            (
                (
                    datetime.strptime(
                        conexion.fecha_hora,
                        "%Y/%m/%d %H:%M:%S.%f"
                    ),
                    conexion
                )
                for conexion in conexiones
            ),
            key=lambda elemento: elemento[0]
        )

        ventanas = defaultdict(deque)
        alertados = set()

        for momento, conexion in conexiones_ordenadas:

            ip = conexion.ip_origen
            eventos = ventanas[ip]

            # Una pausa prolongada inicia un episodio nuevo
            if eventos and momento - eventos[-1] > self.ventana:
                alertados.discard(ip)

            # Eliminar conexiones fuera de la ventana
            while eventos and momento - eventos[0] > self.ventana:
                eventos.popleft()

            # Registrar la conexión actual
            eventos.append(momento)

            # Detectar una ráfaga
            if len(eventos) >= self.umbral_flujos and ip not in alertados:

                alertados.add(ip)

                yield {
                    "tipo": "RAFAGA_DE_FLUJOS",
                    "ip_origen": ip,
                    "cantidad": len(eventos),
                    "inicio": str(eventos[0]),
                    "fin": str(momento)
                }
