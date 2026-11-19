
class ConexionRed:

    def __init__(self, fecha_hora, ip_origen, ip_destino,
                 puerto_destino, protocolo, bytes_transmitidos):

        self.fecha_hora = fecha_hora
        self.ip_origen = ip_origen
        self.ip_destino = ip_destino
        self.puerto_destino = puerto_destino
        self.protocolo = protocolo
        self.bytes_transmitidos = bytes_transmitidos
