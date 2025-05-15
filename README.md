
# Sistema de Detección de Ataques DoS (ICMP)

**IDS semi-automático para detectar ataques de Denegación de Servicio (DoS) basados en ICMP**, como inundaciones de paquetes (*Ping Flood*), *Ping of Death* y variantes. Desarrollado en Python con interfaz gráfica (Tkinter) y Scapy para el análisis de tráfico de red.

---

## Características principales
- **Detección en tiempo real** de ataques ICMP sospechosos.
- **Interfaz gráfica intuitiva** con monitoreo de paquetes y alertas.
- **Umbrales personalizables**: Ajusta la sensibilidad del detector (paquetes/segundo y tiempo de espera).
- **Lista de IPs excluidas**: Ignora direcciones específicas (ej: routers o dispositivos de confianza).
- **Registro de eventos**: Guarda logs detallados en archivos diarios.
- **Soporta múltiples tipos de ataques**:
  - Inundación ICMP (*ICMP Flood*)
  - Ping de la muerte (*Ping of Death*)
  - Ataque Smurf (*Smurf Attack*)
  - Tormenta ICMP (*ICMP Storm*)

---

## Requisitos previos
- **Python 3.8+** (probado en Windows/Linux).
- **Scapy**: Biblioteca para captura y análisis de paquetes.
- **Tkinter**: Para la interfaz gráfica (incluido en Python estándar en la mayoría de sistemas).
- **Permisos de administrador/root**: Necesario para capturar tráfico de red.

---

## Instalación
1. Clona el repositorio:
   ```bash
   git clone https://github.com/tu-usuario/ids-icmp-dos.git
   cd ids-icmp-dos

---
## Imagenes

![image](https://github.com/user-attachments/assets/b1078ac8-6e4d-42ae-b59f-efb1ca244ee6)
![image](https://github.com/user-attachments/assets/402e4a1f-c6f0-45c8-a96a-6e712a2e6721)
![image](https://github.com/user-attachments/assets/0ec5de04-8c76-470c-b467-3c62fd88d442)


