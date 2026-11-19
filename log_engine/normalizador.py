
import re

from security_core.conexion_red import ConexionRed
from log_engine.errores import MalformedLogEntryError
from datetime import datetime
from ipaddress import ip_address

def convertir_ctu13(registro):

    try:

        # Verificar la estructura de la fila CSV
        if None in registro:
            raise ValueError("La fila contiene columnas adicionales")

        if any(
            valor is None
            for clave, valor in registro.items()
            if clave is not None
        ):
            raise ValueError("La fila contiene columnas faltantes")

        conexion = ConexionRed(
            fecha_hora=registro["StartTime"],
            ip_origen=registro["SrcAddr"],
            ip_destino=registro["DstAddr"],
            puerto_destino=registro["Dport"],
            protocolo=registro["Proto"],
            bytes_transmitidos=int(registro["TotBytes"])
        )

        if not str(conexion.ip_origen or "").strip():
            raise ValueError("IP de origen vacía")

        if not str(conexion.ip_destino or "").strip():
            raise ValueError("IP de destino vacía")

        if conexion.bytes_transmitidos < 0:
            raise ValueError("Cantidad de bytes negativa")

                # Determinar el protocolo del registro
        protocolo = str(conexion.protocolo or "").strip().lower()

        if not protocolo:
            raise ValueError("Protocolo vacío")

        # Validar direcciones según el protocolo
        if protocolo == "ipx/spx":

            patron_mac = r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"

            if not re.fullmatch(patron_mac, str(conexion.ip_origen).strip()):
                raise ValueError("Dirección MAC de origen inválida")

            if not re.fullmatch(patron_mac, str(conexion.ip_destino).strip()):
                raise ValueError("Dirección MAC de destino inválida")

        else:
            ip_address(str(conexion.ip_origen).strip())
            ip_address(str(conexion.ip_destino).strip())

        # Validar fecha y hora
        datetime.strptime(
            conexion.fecha_hora,
            "%Y/%m/%d %H:%M:%S.%f"
        )

        # Validar protocolo
        if not str(conexion.protocolo or "").strip():
            raise ValueError("Protocolo vacío")

        return conexion

    except (ValueError, KeyError, TypeError) as error:
        raise MalformedLogEntryError(
            f"CTU-13: {error}"
        ) from error


def convertir_generico(registro):

    try:

        # Verificar la estructura de la fila CSV
        if None in registro:
            raise ValueError("La fila contiene columnas adicionales")

        if any(
            valor is None
            for clave, valor in registro.items()
            if clave is not None
        ):
            raise ValueError("La fila contiene columnas faltantes")

        conexion = ConexionRed(
            fecha_hora=registro["timestamp"],
            ip_origen=registro["src_ip"],
            ip_destino=registro["dst_ip"],
            puerto_destino=registro["dst_port"],
            protocolo=registro["protocol"],
            bytes_transmitidos=int(registro["bytes"])
        )

        if not str(conexion.ip_origen or "").strip():
            raise ValueError("IP de origen vacía")

        if not str(conexion.ip_destino or "").strip():
            raise ValueError("IP de destino vacía")

        if conexion.bytes_transmitidos < 0:
            raise ValueError("Cantidad de bytes negativa")

        # Validar protocolo
        if not str(conexion.protocolo or "").strip():
            raise ValueError("Protocolo vacío")

        # Validar direcciones IP
        ip_address(str(conexion.ip_origen).strip())
        ip_address(str(conexion.ip_destino).strip())

        # Validar fecha y hora
        datetime.strptime(
            str(conexion.fecha_hora),
            "%Y/%m/%d %H:%M:%S.%f"
        )

        return conexion

    except (ValueError, KeyError, TypeError) as error:
        raise MalformedLogEntryError(
            f"Registro genérico: {error}"
        ) from error
