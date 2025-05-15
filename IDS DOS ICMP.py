# Importacion de las bibliotecas que se necesitan para hacer el detector de DOS
import tkinter as tk  # Esta es la biblioteca principal para hacer interfaces graficas en Python
from tkinter import ttk, scrolledtext, messagebox
""" ttk tiene estilos variados para tkinter. scrolledtext: este combina un área de texto con una barra de desplazamiento para que podamos desplazar hacia abajo arriba de la ventana, messagebox es para cuadros mostrar mensajes como alertas"""
from scapy.all import sniff, IP, ICMP, conf  # Scapy nos ayuda a capturar paquetes de red
from datetime import datetime  # Para trabajar con fechas y horas
import os, threading, time  # os para trabajar con archivos del sistema, threading son hilos para hacer varias cosas al mismo tiempo, time para medir tiempos
from collections import defaultdict  # para hacer listas que no dan error


# Aquí guardamos cosas importantes que vamos a usar en todo el programa
ventana = None  # varaible de la ventana principal
ejecutando = False  # Para saber si el detect
pausado = False  # Para saber si está en pausa
hilo_sniffer = None  # Esto nos ayuda a revisar la red sin que se congele el programa
paquetes_totales = amenazas_totales = 0  # Para contar cuántos paquetes y amenazas se han encontrado
IPS_EXCLUIDAS = {'192.168.100.1'}  # Lista de direcciones que no se van a escanear 


# Aquí guardamos información útil para el programa
TIPOS_ICMP = {0: "Echo Reply", 3: "Destino Inalcanzable", 8: "Echo Request (Ping)", 11: "Tiempo Excedido"}  # Los diferentes tipos de mensajes que podemos recibir
COLORES = {'fondo': '#f0f2f5', 'texto': '#2c3e50', 'acento': '#3498db', 'alerta': '#e74c3c', 'exito': '#2ecc71'}  # colores que tendra la interfaz
elementos_ui = {}  # Aquí guardamos todas las partes de la interfaz como botones, textos, etc.

def crear_estadisticas_default():
    """Esta función crea una especie de diccionario de información para cada ip que vemos en la red"""
    return {
        'solicitudes': 0,  # Cuántas veces hemos visto esta ip
        'ultimo_tiempo': time.time(),  # La última vez que vimos algo de esta ip
        'tiempo_inicio': time.time(),  # Cuándo empezamos a ver esta ip
        'puertos_afectados': set(),  # A qué partes de la red intenta conectarse
        'paquetes_grandes': 0,  # Cuántos mensajes grandes ha enviado una ip
        'tipos_icmp': set()  # Qué tipos de mensajes está enviando
    }

# Creamos un lugar para guardar la información de cada ip que vemos
estadisticas_icmp = defaultdict(crear_estadisticas_default)

def guardar_registro(mensaje, tipo="INFO"):
    """Esta función es como un diario que guarda todo lo que pasa en el programa"""
    try:
        #  la fecha de hoy en el nombre del archivo para identificar cuando se hizo el escaner
        fecha = datetime.now().strftime("%Y-%m-%d")
        # se abre el archivo para escribir informacion encontrada como amenazas
        with open(f"registros/registro_dos_{fecha}.log", "a", encoding="utf-8") as f:
            # el programa escribe que paso y cuándo paso
            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [{tipo}] {mensaje}\n")
    except Exception as e:
        print(f"hubo un error guardando el mensaje: {e}")

def actualizar_interfaz(mensaje, es_amenaza=False):
    """Esta función actualiza lo que vemos en la pantalla cuando pasa algo"""
    global paquetes_totales, amenazas_totales  # Usamos los contadores globales que estan arriba (variables)
    if es_amenaza:
        # Si encontramos algo peligroso se mostrara en color rojo
        """Insertamos el mensaje en la caja de texto que muestra las amenazas.
         'tk.END' significa que el mensaje se añadirá al final del texto que ya está en la caja."""
        elementos_ui['texto_amenazas'].insert(tk.END, f"{mensaje}\n")
        """Nos aseguramos de que la caja de texto se desplace hasta el final, para que podamos ver el nuevo mensaje."""
        elementos_ui['texto_amenazas'].see(tk.END)  # Nos movemos al final para verlo
        """Incrementamos el contador de amenazas en 1, porque hemos detectado una nueva amenaza."""
        amenazas_totales += 1  # Sumamos uno al contador de amenazas
        """Actualizamos el texto de la etiqueta que muestra el número total de amenazas detectadas."""
        elementos_ui['etiqueta_amenazas'].config(text=f"⚠️ Amenazas: {amenazas_totales}")  # Actualizamos el número que se ve
    else:
        """Si el mensaje no es una amenaza (es_amenaza es False):
        Insertamos el mensaje en la caja de texto que muestra los paquetes normales."""
        elementos_ui['texto_paquetes'].insert(tk.END, f"{mensaje}\n")
        """Nos aseguramos de que la caja de texto se desplace hasta el final, para que podamos ver el nuevo mensaje."""
        elementos_ui['texto_paquetes'].see(tk.END)
        """Incrementamos el contador de paquetes en 1, porque hemos detectado un nuevo paquete."""
        paquetes_totales += 1
        """Actualizamos el texto de la etiqueta que muestra el número total de paquetes detectados."""
        elementos_ui['etiqueta_paquetes'].config(text=f"Paquetes: {paquetes_totales}")

def procesar_paquete(paquete):
    """Esta función analiza cada paquete de red que llega"""
    if not (IP in paquete and ICMP in paquete) or pausado or paquete[IP].src in IPS_EXCLUIDAS:
        return

    ip_origen = paquete[IP].src
    tiempo_actual = time.time()
    stats = estadisticas_icmp[ip_origen]
    
    if tiempo_actual - stats['ultimo_tiempo'] > 10:
        stats.update(crear_estadisticas_default())
    
    stats['solicitudes'] += 1
    stats['ultimo_tiempo'] = tiempo_actual
    stats['puertos_afectados'].add(paquete[IP].dst)
    stats['tipos_icmp'].add(paquete[ICMP].type)
    
    if len(paquete) > 1500:
        stats['paquetes_grandes'] += 1

    tipo = TIPOS_ICMP.get(paquete[ICMP].type, f"Tipo {paquete[ICMP].type}")
    info = f"[{datetime.now().strftime('%H:%M:%S')}] {ip_origen} → {paquete[IP].dst}\n     Mensaje: {tipo}"
    actualizar_interfaz(info)

    try:
        icmp_por_segundo = int(elementos_ui['entrada_icmp_por_segundo'].get())
        tiempo_espera = int(elementos_ui['entrada_tiempo_espera'].get())
    except ValueError:
        icmp_por_segundo, tiempo_espera = 500, 5

    tiempo_total = tiempo_actual - stats['tiempo_inicio']
    
    if tiempo_total > 0:
        pps = stats['solicitudes'] / tiempo_total
        ataques = []

        if pps > icmp_por_segundo and tiempo_total >= tiempo_espera:
            ataques.append("INUNDACIÓN ICMP")
        if stats['paquetes_grandes'] > 50:
            ataques.append("PING DE LA MUERTE")
        if len(stats['puertos_afectados']) > 100:
            ataques.append("ATAQUE SMURF")
        if len(stats['tipos_icmp']) > 8:
            ataques.append("TORMENTA ICMP")

        if ataques:
            alerta = f"\n ¡ATAQUE DoS DETECTADO!\n"
            alerta += f" IP Atacante: {ip_origen}\n"
            alerta += f" Mensajes/s: {pps:.2f}\n"
            alerta += f" Tipos de ataque: {', '.join(ataques)}"
            
            actualizar_interfaz(alerta, True)
            guardar_registro(f"Ataque DoS - IP: {ip_origen} - PPS: {pps:.2f} - Ataques: {', '.join(ataques)}", "ALERTA")
            stats.update(crear_estadisticas_default())

def iniciar_detector():
    """Esta función inicia el detector de ataques"""
    global ejecutando, hilo_sniffer

    if not ejecutando:
        ejecutando = True
        
        for widget in ['boton_iniciar', 'entrada_icmp_por_segundo', 'entrada_tiempo_espera']:
            elementos_ui[widget].config(state='disabled')
        
        for widget in ['boton_detener', 'boton_pausar']:
            elementos_ui[widget].config(state='normal')
        
        hilo_sniffer = threading.Thread(target=lambda: [
            setattr(conf, 'sniff_promisc', True),
            setattr(conf, 'promisc', True),
            [sniff(prn=procesar_paquete, store=0, filter="icmp", count=1) for _ in iter(lambda: ejecutando, False)]
        ])
        
        hilo_sniffer.daemon = True
        hilo_sniffer.start()
        
        elementos_ui['barra_estado'].config(text="Estado: Detector activo - Buscando ataques...")
        actualizar_interfaz(" Detector iniciado - Buscando ataques DoS...\n")

def detener_detector():
    """Esta función detiene el detector"""
    global ejecutando, pausado
    ejecutando = pausado = False

    if hilo_sniffer:
        hilo_sniffer.join(timeout=1)

    for widget in ['boton_iniciar', 'entrada_icmp_por_segundo', 'entrada_tiempo_espera']:
        elementos_ui[widget].config(state='normal')

    for widget in ['boton_detener', 'boton_pausar']:
        elementos_ui[widget].config(state='disabled')

    elementos_ui['barra_estado'].config(text="Estado: Detector apagado")
    actualizar_interfaz("⏹️ Detector apagado.\n")

def pausar_detector():
    """Esta función pausa o reanuda el detector"""
    global pausado
    pausado = not pausado
    
    estado = "pausado" if pausado else "reanudado"
    elementos_ui['boton_pausar'].config(text="▶ Reanudar" if pausado else "⏸ Pausar")
    elementos_ui['barra_estado'].config(text=f"Estado: Detector {estado}")
    actualizar_interfaz(f"⏯️ Detector {estado}.\n")

def agregar_ip_excluida():
    """Esta función permite agregar IPs a la lista de exclusión"""
    dialogo = tk.Toplevel(ventana)
    dialogo.title("Agregar IP")
    dialogo.geometry("300x100")
    dialogo.configure(bg=COLORES['fondo'])
    
    dialogo.transient(ventana)
    dialogo.grab_set()
    
    tk.Label(dialogo, text="IP:", bg=COLORES['fondo'], fg=COLORES['texto']).pack(pady=5)
    entrada_ip = tk.Entry(dialogo, width=20)
    entrada_ip.pack(pady=5)
    
    def guardar():
        ip = entrada_ip.get().strip()
        if ip:
            IPS_EXCLUIDAS.add(ip)
            actualizar_lista_ips()
            dialogo.destroy()
            messagebox.showinfo("Éxito", f"IP {ip} agregada")
        else:
            messagebox.showwarning("Error", "Ingrese una IP válida")
    
    tk.Button(dialogo, text="Guardar", command=guardar,
              bg=COLORES['exito'], fg='white').pack(pady=5)

def eliminar_ip_excluida():
    """Esta función elimina IPs de la lista de exclusión"""
    seleccion = elementos_ui['lista_ips'].curselection()
    
    if not seleccion:
        messagebox.showwarning("Error", "Seleccione una IP")
        return
    
    ip = elementos_ui['lista_ips'].get(seleccion)
    
    if messagebox.askyesno("Confirmar", f"¿Eliminar IP {ip}?"):
        IPS_EXCLUIDAS.remove(ip)
        actualizar_lista_ips()

def actualizar_lista_ips():
    """Esta función actualiza la lista de IPs excluidas en la interfaz"""
    elementos_ui['lista_ips'].delete(0, tk.END)
    for ip in sorted(IPS_EXCLUIDAS):
        elementos_ui['lista_ips'].insert(tk.END, ip)

def crear_interfaz():
    """Esta función crea la interfaz gráfica del programa"""
    global ventana
    
    ventana = tk.Tk()
    ventana.title("Sistema de Detección de Ataques DoS (IDS)")
    ventana.geometry("1200x800")
    ventana.configure(bg=COLORES['fondo'])
    
    # Crear encabezado
    header = tk.Frame(ventana, bg=COLORES['texto'], height=80)
    header.pack(fill='x', padx=0, pady=0)
    header.pack_propagate(False)
    
    tk.Label(header, text="🛡️ Sistema de Detección de Ataques DoS (IDS)",
             bg=COLORES['texto'], fg='white', font=('Helvetica', 16, 'bold')).pack(pady=(10,0))
    
    # Panel de control
    panel = tk.Frame(ventana, bg=COLORES['fondo'])
    panel.pack(fill='x', padx=20, pady=10)
    
    # Botones principales
    for btn in [
        ('boton_iniciar', '▶ Iniciar', iniciar_detector, COLORES['exito']),
        ('boton_detener', '⬛ Detener', detener_detector, COLORES['alerta']),
        ('boton_pausar', '⏸ Pausar', pausar_detector, COLORES['acento'])
    ]:
        elementos_ui[btn[0]] = tk.Button(panel, text=btn[1], command=btn[2],
                                       bg=btn[3], fg='white', font=('Helvetica', 11),
                                       width=12, relief='flat', cursor='hand2')
        elementos_ui[btn[0]].pack(side='left', padx=5)
    
    # Campos de configuración
    for cfg in [('entrada_icmp_por_segundo', 'ICMP por segundo:', '100'),
               ('entrada_tiempo_espera', 'Tiempo de espera (s):', '5')]:
        tk.Label(panel, text=cfg[1], bg=COLORES['fondo'],
                fg=COLORES['texto'], font=('Helvetica', 11)).pack(side='left', padx=10)
        elementos_ui[cfg[0]] = tk.Entry(panel, width=10)
        elementos_ui[cfg[0]].pack(side='left', padx=5)
        elementos_ui[cfg[0]].insert(0, cfg[2])
    
    # Contadores
    stats = tk.Frame(panel, bg=COLORES['fondo'])
    stats.pack(side='right')
    for lbl in [('etiqueta_paquetes', '📊 Paquetes: 0'),
               ('etiqueta_amenazas', '⚠️ Amenazas: 0')]:
        elementos_ui[lbl[0]] = tk.Label(stats, text=lbl[1], bg=COLORES['fondo'],
                                      fg=COLORES['texto'], font=('Helvetica', 12))
        elementos_ui[lbl[0]].pack(side='left', padx=15)
    
    # Panel central
    central = tk.Frame(ventana, bg=COLORES['fondo'])
    central.pack(fill='both', expand=True, padx=20, pady=5)
    
    # Panel de IPs excluidas
    panel_ips = tk.LabelFrame(central, text="IPs Excluidas", bg=COLORES['fondo'],
                           fg=COLORES['texto'], font=('Helvetica', 11))
    panel_ips.pack(side='left', fill='y', padx=5)
    
    elementos_ui['lista_ips'] = tk.Listbox(panel_ips, width=20, height=10)
    elementos_ui['lista_ips'].pack(pady=5, padx=5)
    actualizar_lista_ips()
    
    frame_botones_ip = tk.Frame(panel_ips, bg=COLORES['fondo'])
    frame_botones_ip.pack(fill='x', padx=5, pady=5)
    tk.Button(frame_botones_ip, text="Agregar", command=agregar_ip_excluida,
             bg=COLORES['exito'], fg='white').pack(side='left', padx=2)
    tk.Button(frame_botones_ip, text="Eliminar", command=eliminar_ip_excluida,
             bg=COLORES['alerta'], fg='white').pack(side='left', padx=2)
    
    # Panel de monitoreo
    panel_monitoreo = tk.Frame(central, bg=COLORES['fondo'])
    panel_monitoreo.pack(side='right', fill='both', expand=True)
    
    for area in [('texto_paquetes', 'Monitoreo', COLORES['texto']),
                ('texto_amenazas', '⚠️ Alertas', COLORES['alerta'])]:
        frame = tk.LabelFrame(panel_monitoreo, text=area[1], bg=COLORES['fondo'],
                          fg=area[2], font=('Helvetica', 12, 'bold'))
        frame.pack(side='left' if area[0] == 'texto_paquetes' else 'right',
                fill='both', expand=True, padx=5)
        elementos_ui[area[0]] = scrolledtext.ScrolledText(frame, bg=COLORES['fondo'],
                                                      fg=area[2], font=('Consolas', 10))
        elementos_ui[area[0]].pack(fill='both', expand=True, pady=5, padx=5)
    
    # Barra de estado
    status = tk.Frame(ventana, bg=COLORES['texto'], height=30)
    status.pack(fill='x', side='bottom')
    status.pack_propagate(False)
    elementos_ui['barra_estado'] = tk.Label(status, text="Estado: Listo",
                                        bg=COLORES['texto'], fg='white',
                                        font=('Helvetica', 10))
    elementos_ui['barra_estado'].pack(side='left', padx=10, pady=5)
    
    # Configuración de cierre
    ventana.protocol("WM_DELETE_WINDOW", lambda: [setattr(ventana, 'ejecutando', False), ventana.quit()])

if __name__ == "__main__":
    # Verificar permisos de administrador
    try:
        es_admin = os.getuid() == 0
    except AttributeError:
        import ctypes
        es_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0

    if not es_admin:
        print("[!] AVISO: Este programa necesita permisos de administrador")

    # Crear directorio de registros
    os.makedirs("registros", exist_ok=True)

    # Iniciar la interfaz
    crear_interfaz()
    ventana.mainloop()
