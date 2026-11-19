
class Host:

    def __init__(self, ip):
        self.ip = ip
        self.total_conexiones = 0
        self.total_bytes = 0

    def registrar_conexion(self, conexion):

        if conexion.ip_origen != self.ip:
            raise ValueError("La conexión no pertenece a este host")

        self.total_conexiones += 1
        self.total_bytes += int(conexion.bytes_transmitidos)

    def mostrar_resumen(self):

        print("IP:", self.ip)
        print("Conexiones:", self.total_conexiones)
        print("Bytes:", self.total_bytes)
