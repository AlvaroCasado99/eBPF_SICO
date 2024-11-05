# eBPF_SICO

-Crear un programa que:
1. Cree un fichero `trampa.txt` en algun lugar del sistema
2. Un programa en ebpf que:
    - Detecte que alguien ha abierto `trampa.txt` 
    - Cierre la sesión del ususario
3. Logguear en un fichero que usuario accede a `trampa.txt` y guardarlo en un fichero.
